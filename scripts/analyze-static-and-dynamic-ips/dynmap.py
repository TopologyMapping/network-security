#!/usr/bin/env python3

# Needed for analysis
import math
import statistics
import pathlib
import pyasn
import ipaddress
import datetime as dt
import subprocess
from collections import defaultdict

# Code quality
import pickle
import logging
import argparse

# Code consistency
from typing import Any

# IP address time series
IpTimeSeries = list[tuple[dt.datetime, str, int, str]]
"""
List of time series entries, each as a tuple (timestamp, fingerprint, port, domain)
"""


class IP_Block:
    """
    Represents a block of contiguous IP addresses.

    Not all IPs are actually present in the block, only the ones that were observed in the original scans.
    Present IPs are called "true" IPs.

    A block also has a type, which is used to classify the block as dynamic, static, proxy, cluster, etc.
    """

    def __init__(self):
        self.type: str = ""
        self.start: int = 0
        self.end: int = 0
        self.startStr: str = ""
        self.endStr: str = ""

        self.trueIps: list[str] = list()

    def setType(self, type: str):
        self.type = type

    def setStart(self, ip: int):
        self.start = ip
        self.startStr = str(ipaddress.IPv4Address(ip))

    def setEnd(self, ip: int):
        self.end = ip
        self.endStr = str(ipaddress.IPv4Address(ip))

    def addTrueIp(self, ip: int):
        self.trueIps.append(str(ipaddress.IPv4Address(ip)))

    def getTrueIps(self) -> list[str]:
        return self.trueIps

    def getFullIps(self) -> list[str]:
        return [
            str(ipaddress.IPv4Address(ip)) for ip in range(self.start, self.end + 1)
        ]

    def getSize(self):
        return self.end - self.start + 1

    def getTrueSize(self):
        return len(self.trueIps)


def initParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyzes IP addresses from a set of observations relating an IP address to a fingerprint in order to find dynamic IP addresses. You need to preprocess your data source first."
    )

    parser.add_argument(
        "-c",
        "--cache-folder",
        type=str,
        dest="cacheFolder",
        action="store",
        default="cache",
        help="folder to search for previously cached input data. If cached input data is not available, you will need to preprocess your data source first. (default: %(default)s)",
    )

    parser.add_argument(
        "-b",
        "--min-block-size",
        type=int,
        dest="minBlockSize",
        action="store",
        default=8,
        help="minimum IP block size. This controls the granularity of the search for dynamic IP addresses (default: %(default)s)",
    )

    parser.add_argument(
        "-g",
        "--max-gap-size",
        type=int,
        dest="maxGapSize",
        action="store",
        default=8,
        help="maximum continuous gap allowed in an IP block. This controls the tolerance for missing IP addresses (default: %(default)s)",
    )

    parser.add_argument(
        "-t",
        "--entropy-smoothing-threshold",
        type=float,
        dest="entropySmoothingThreshold",
        metavar="THRESHOLD",
        action="store",
        default=0.5,
        help="normalized sample IP usage entropy threshold (NSUE). A median filter is applied to IP addresses with NSUE lower than the threshold (default: %(default)s)",
    )

    parser.add_argument(
        "-w",
        "--median-filter-window-size",
        type=int,
        dest="medianFilterWindowSize",
        metavar="WINDOWSIZE",
        action="store",
        default=5,
        help="median filter window size. This controls the amount of neighbors used when smoothing IP addresses. Setting this to 1 will disable the median filter (default: %(default)s)",
    )

    parser.add_argument(
        "-s",
        "--save-ips",
        dest="shouldSaveIps",
        action="store_true",
        default=False,
        help="if enabled, will save dynamic IP addresses found as a .pickle file (default: %(default)s)",
    )

    parser.add_argument(
        "-f",
        "--logfile",
        type=str,
        dest="logfile",
        action="store",
        default=None,
        help="file to store log outputs. If not specified, logs will be printed on screen",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        type=str,
        dest="loglevel",
        metavar="LOGLEVEL",
        action="store",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default="INFO",
        help="log level. Available options: DEBUG, INFO, WARN, ERROR, FATAL (default: %(default)s)",
    )

    return parser


def calculateDomainNameEntropy(timeSeries: IpTimeSeries) -> float:
    """
    Calculates the "entropy" of domain names in a time series.

    The entropy is calculated as the ratio of unique domain names and unique fingerprints.
    The ratio is calculated on a port by port basis, and the smallest ratio is returned.

    Parameters
    ----------
    `timeSeries`: a time series for a given IP address.

    Returns
    -------
    `ratio`: the smallest domain to fingerprint ratio found in the time series as described above.
    """

    # Using float(inf) leads to some issues, so we are using this instead
    smallestRatio: float = 3.0

    # Default dict magic
    uniqueDomainsAndFingerprints: dict[int, tuple[set[str], set[tuple]]] = defaultdict(
        lambda: (set(), set())
    )

    for _, fingerprint, port, domain in timeSeries:
        uniqueDomainsAndFingerprints[port][0].add(fingerprint)
        uniqueDomainsAndFingerprints[port][1].add(domain)

    for fingerprints, domains in uniqueDomainsAndFingerprints.values():
        # Discard ports with just one domain, since there are no changes (this port has static behavior)
        if len(domains) == 1:
            continue

        ratio: float = len(domains) / len(fingerprints)

        # Clamp (should not happen, but just in case)
        if ratio > 1.0:
            ratio = 1.0

        smallestRatio = min(smallestRatio, ratio)

    # If smallestRatio was not updated, it will be 3.0, so return 0.0
    return smallestRatio if smallestRatio < 2.0 else 0.0


def buildBlocks(
    args: argparse.Namespace,
    contiguousIps: list[int],
    fingerprintsPerIp: dict[str, set[str]],
) -> list[IP_Block]:
    """
    Build IP blocks (non-overlapping) from a list of contiguous IP addresses.

    Every valid block is defined as:
    - has at least MIN_BLOCK_SIZE
    - max gap size is no more than MAX_GAP_SIZE
    - start and end IPs must be in the contiguousIps list

    An IP gap is considered as any IP that is not in the contiguousIps list (has not been observed in the scans)
    or that has only one fingerprint.

    Adapted from: 'How Dynamic are IP Addresses?' (https://dl.acm.org/doi/abs/10.1145/1282380.1282415) Section 4.2

    Parameters
    ----------
    `args`: command line arguments
    `contiguousIps`: a list of contiguous IP addresses as integers.
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address.

    Returns
    -------
    `IP_Blocks`: a list of IP blocks found in the list of contiguous IP addresses.
    """

    blocksFound: list[IP_Block] = list()

    currentIdx: int = 0

    # Scan list sequentially, trying to build the biggest possible blocks
    while currentIdx < len(contiguousIps):
        block: IP_Block = IP_Block()

        lastIp: int = contiguousIps[currentIdx]

        block.setStart(lastIp)
        block.setEnd(lastIp)
        block.addTrueIp(lastIp)

        currentIdx += 1

        # Adapted from: 'How Dynamic are IP Addresses?' (https://dl.acm.org/doi/abs/10.1145/1282380.1282415)
        # Refer to section 4.2

        # Try to build a block such that:
        # - it has at least MIN_BLOCK_SIZE
        # - max gap size is no more than MAX_GAP_SIZE
        # - start and end IPs must be in the contiguousIps list

        # An IP gap is considered as any IP that is not in the contiguousIps list (has not been observed)
        # or that has only one fingerprint

        while currentIdx < len(contiguousIps):
            currentIp: int = contiguousIps[currentIdx]

            hasJustOneFingerprint: bool = (
                len(fingerprintsPerIp[str(ipaddress.IPv4Address(currentIp))]) <= 1
            )

            if hasJustOneFingerprint:
                # Skip this IP, since it is considered a gap
                currentIdx += 1
                continue

            gapSize: int = currentIp - lastIp + 1

            # A significant gap has been found, so this block ends here
            if gapSize > args.maxGapSize:
                break

            # Gap is tolerable, so add IP to the block and get next IP
            block.addTrueIp(currentIp)
            block.setEnd(currentIp)

            lastIp = currentIp
            currentIdx += 1

        # We can finish this block or discard it
        # Either way, we advance to start a new block
        if block.getSize() >= args.minBlockSize:
            blocksFound.append(block)

    return blocksFound


def findSubBlocks(
    args: argparse.Namespace,
    block: IP_Block,
    entropy: dict[str, float],
    fingerprintsPerIp: dict[str, set[str]],
) -> list[IP_Block]:
    """
    Finds sub blocks (non-overlapping) within a given IP block.

    A sub block is defined as a block that has at least one IP with entropy higher than the smoothing threshold.
    All IPs with entropy lower than the threshold ("dips") are discarded.

    Parameters
    ----------
    `args`: command line arguments
    `block`: the IP block to analyze.
    `entropy`: a dict of normalized sample IP usage entropy values per IP address.
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address.

    Returns
    -------
    `IP_Blocks`: a list of sub IP blocks found in the block (may be empty).
    """

    subBlocksFound: list[IP_Block] = list()

    currentIdx: int = 0
    blockFullIps: list[str] = block.getFullIps()

    # Scan list sequentially, discarding "dips" (aka entropy < smoothing threshold)
    while currentIdx < block.getSize():
        currentIp: str = blockFullIps[currentIdx]

        # Skip low entropy IPs until we find a good IP
        if abs(entropy[currentIp]) < args.entropySmoothingThreshold:
            currentIdx += 1
            continue

        subBlock: IP_Block = IP_Block()
        subBlock.setType(block.type)

        # Block start
        initialIp: int = int(ipaddress.IPv4Address(currentIp))

        subBlock.setStart(initialIp)
        subBlock.setEnd(initialIp)

        # An IP is considered "true" if it was originally seen on the initial scan
        if currentIp in fingerprintsPerIp.keys():
            subBlock.addTrueIp(initialIp)

        currentIdx += 1

        while currentIdx < block.getSize():
            currentIp: str = blockFullIps[currentIdx]
            currentIpInt: int = int(ipaddress.IPv4Address(currentIp))

            # An IP with low entropy has been found
            # Finish this block and advance
            if abs(entropy[currentIp]) < args.entropySmoothingThreshold:
                currentIdx += 1
                break

            # Add IP to the block and get next IP
            subBlock.setEnd(currentIpInt)

            if currentIp in fingerprintsPerIp.keys():
                subBlock.addTrueIp(currentIpInt)

            currentIdx += 1

        subBlocksFound.append(subBlock)

    return subBlocksFound


def getBlockUniqueDataAmount(
    blockIps: list[str], timeSeries: dict[str, IpTimeSeries]
) -> tuple[int, int]:
    """
    Calculates the amount of unique domains and fingerprints found in a block.

    Parameters
    ----------
    `blockIps`: a list of IP addresses in the block.
    `timeSeries`: a dict of a timeseries for each IP address.

    Returns
    -------
    A tuple in the following order:
    `uniqueDomains`: amount of unique domains found in the block.
    `uniqueFingerprints`: amount of unique fingerprints found in the block.
    """

    allDomains: set[str] = set()
    allFingerprints: set[str] = set()

    for ip in blockIps:
        for _, fingerprint, _, domain in timeSeries[ip]:
            allDomains.add(domain)
            allFingerprints.add(fingerprint)

    return len(allDomains), len(allFingerprints)


def getCombinedEntropyAndType(
    usageEntropy: float,
    domainEntropy: float,
    uniqueBlockDomains: int,
    uniqueBlockFingerprints: int,
    blockTrueSize: int,
) -> tuple[float, str]:
    """
    Combines IP usage and domain entropies into a single metric and determines the type of an IP address.

    A set of special rules is applied to achieve this result. This function is the core of DynMap.

    Parameters
    ----------
    `usageEntropy`: the normalized sample IP usage entropy.
    `domainEntropy`: the domain entropy.
    `uniqueBlockDomains`: the amount of unique domains found in the block.
    `uniqueBlockFingerprints`: the amount of unique fingerprints found in the block.
    `blockTrueSize`: the true size of the block (amount of IPs that are present in the original Shodan scans).

    Returns
    -------
    A tuple in the following order:
    `combinedEntropy`: the combined entropy of the IP address.
    `type`: the type of the IP address (dynamic, static, proxy, cluster, outlier).
    """

    # CASE 1: If both entropies are too low, this IP is likely static
    # We will just average entropies, this IP WILL BE DISCARDED when building sub blocks
    # We set type to static
    if usageEntropy < 0.2 and domainEntropy < 0.2:
        return ((usageEntropy + domainEntropy) / 2, "static")

    # CASE 2: If both entropies are high, this IP is likely dynamic
    # So we average entropies and set type to dynamic
    if usageEntropy > 0.8 and domainEntropy > 0.8:
        return ((usageEntropy + domainEntropy) / 2, "dynamic")

    # Special cases
    # CASE 3: Usage entropy is too low but domain entropy is high
    # This IP is likely dynamic if there are enough domain changes, so we set its combined entropy to high
    if usageEntropy < 0.2 and domainEntropy > 0.8:
        return (domainEntropy, "dynamic")

    # CASE 4: Usage entropy is high but domain entropy is too low
    # We will check whether or not this IP has a lot of fingerprints and domains
    # This IP might be part of a cluster or a proxy block
    if usageEntropy > 0.8 and domainEntropy < 0.2:
        fgRatio: float = uniqueBlockFingerprints / blockTrueSize
        dmRatio: float = uniqueBlockDomains / blockTrueSize

        # CASE 4.1: Lots of fingerprints and domains ACROSS THE WHOLE BLOCK,
        # this IP is likely dynamic and part of a host provider or something similar
        if fgRatio > 0.5 and dmRatio > 0.5:
            return (usageEntropy, "dynamic")

        if dmRatio <= 0.5:
            # CASE 4.2 and 4.3: Few domains ACROSS THE WHOLE BLOCK,
            # If the amount of fingerprints is significant for this block size,
            # this IP might be part of a cluster, otherwise it might be a proxy IP
            if fgRatio >= 0.5:
                return (usageEntropy, "cluster")
            else:
                return (usageEntropy, "proxy")

        # CASE 4.4: Few fingerprints ACROSS THE WHOLE BLOCK, but lots of domains
        # This should not happen, but if it does, we will consider this IP an outlier and ignore it
        return (usageEntropy, "outlier")

    # CASE 5: If an IP doesn't fall into any category stated above, we may have an IP that is not
    # sufficiently dynamic nor static, so we average entropies and let the smoothing and
    # sub block processes decide whether or not to include this IP in the resulting dynamic IPs
    return ((usageEntropy + domainEntropy) / 2, "dynamic")


def findDynamicIps(
    args: argparse.Namespace,
    fingerprintsPerIp: dict[str, set[str]],
    ipsPerFingerprint: dict[str, set[str]],
    ipFingerprintsOverTime: dict[str, IpTimeSeries],
) -> tuple[list[str], list[str], list[str]]:
    """
    Analyzes a collection of IP addresses and applies a set of rules searching for dynamic IP addresses.

    If the log level is set to `DEBUG`, a trace of blocks found will be logged,
    as well as detailed information about the IPs found in each block.

    Parameters
    ----------
    `args`: command line arguments
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address
    `ipsPerFingerprint`: a dict of unique IP addresses found per fingerprint
    `ipFingerprintsOverTime`: a dict of a timeseries for each IP address

    Returns
    -------
    A tuple in the following order:
    `allDynamicIps`: a list of all true + extra dynamic IP addresses found
    `allProxyIps`: a list of all true + extra proxy IP addresses found
    `allClusterIps`: a list of all true + extra cluster IP addresses found
    """

    # Init pyasn
    asndb = pyasn.pyasn(f"{args.cacheFolder}/IPASN.dat")

    # Separate IPs per AS Number and BGP prefix
    logging.info(
        f"Finding AS numbers and BGP prefixes for {len(fingerprintsPerIp)} IP addresses"
    )

    ipsPerAS: dict[tuple[str, str], list[int]] = defaultdict(list)

    for ip in fingerprintsPerIp.keys():
        (asn, prefix) = asndb.lookup(ip)

        if asn == None:
            continue

        # Convert to integer value for easier block building
        ipsPerAS[(asn, prefix)].append(int(ipaddress.IPv4Address(ip)))

    logging.info(f"Found {len(ipsPerAS)} unique (AS number, prefix) tuples")
    logging.info(
        f"Found {sum(len(ips) >= args.minBlockSize for ips in ipsPerAS.values())} ASes with {args.minBlockSize} or more IP addresses"
    )

    # Start building blocks
    logging.info(f"Building blocks")

    blocks: list[IP_Block] = list()

    for ips in ipsPerAS.values():
        if len(ips) >= args.minBlockSize:
            ips.sort()
            blocks.extend(buildBlocks(args, ips, fingerprintsPerIp))

    logging.info(f"Built {len(blocks)} blocks")

    logging.debug("Block data dumps:")

    for b in blocks:
        logging.debug(
            f"BLOCK  Start: {b.startStr}  End: {b.endStr}  Size: {b.getSize()}  True Size: {b.getTrueSize()}"
        )

        for ip in b.getTrueIps():
            logging.debug(f"{ip}")

        logging.debug("")

    # IP Usage-Entropy Computation
    # Adapted from: 'How Dynamic are IP Addresses?' (https://dl.acm.org/doi/abs/10.1145/1282380.1282415)
    logging.info(f"Calculating IP Usage-Entropy and IP Domain-Entropy")

    combinedEntropy: dict[str, float] = defaultdict(float)

    # The analysis is done on a block by block basis
    for block in blocks:
        # Calculate amount of unique fingerprints and domains for later use when combining entropies
        (uniqueDomains, uniqueFingerprints) = getBlockUniqueDataAmount(
            block.getTrueIps(), ipFingerprintsOverTime
        )

        # Track types assigned to IPs by the getCombinedEntropy function, this is used to assign a type to the whole block
        types: dict[str, int] = {
            "dynamic": 0,
            "proxy": 0,
            "cluster": 0,
            "outlier": 0,
            "static": 0,
        }

        # We want to know the probability of fingerprints from an IPj from block A
        # to appear in other IPs from the same block
        for ip in block.getTrueIps():
            entropy: float = 0.0

            # We don't build the matrix Aj directly, instead we precalculate the sum of every column
            # Please refer to the section 4.3 of the paper mentioned above
            Aj: list[int] = [
                len(fingerprintsPerIp[ipB].intersection(fingerprintsPerIp[ip]))
                for ipB in block.getTrueIps()
                if ipB != ip
            ]
            zj: int = sum(Aj)

            if zj > 0:
                entropy = -sum((ak / zj) * math.log2((ak / zj)) for ak in Aj if ak > 0)

            # Normalized IP Usage Entropy and Normalized Sample IP Usage Entropy
            nue: float = entropy / math.log2(block.getSize())
            nsue: float = entropy / math.log2(
                sum(ak > 0 for ak in Aj) + 1 + int(zj == 0)
            )

            # This IP has definitely more than one fingerprint by this point, so
            # we favor IPs with a domain name change (on a given port) to mitigate the effect of IPs which have
            # different fingerprints because of SSL certificate renewals
            # We do this by using a domain name entropy
            normalizedDomainEntropy: float = calculateDomainNameEntropy(
                ipFingerprintsOverTime[ip]
            )

            # Combine entropies using a set of rules
            (combinedEntropy[ip], ipType) = getCombinedEntropyAndType(
                nsue,
                normalizedDomainEntropy,
                uniqueDomains,
                uniqueFingerprints,
                block.getTrueSize(),
            )

            types[ipType] += 1

            # Timeseries and entropy debug info
            logging.debug(f"Time series for IP address: {ip}")

            for timestamp, fingerprint, port, domain in ipFingerprintsOverTime[ip]:
                logging.debug(
                    f"T: {timestamp}  P: {port}  F: {fingerprint}  D: {domain}"
                )

            logging.debug(
                f"IP: {ip}  Entropy: {nsue}  Domain Entropy: {normalizedDomainEntropy}  Combined Entropy: {combinedEntropy[ip]}  Type: {ipType}  Unique Fingerprints: {uniqueFingerprints}  Unique Domains: {uniqueDomains}  Block true size {block.getTrueSize()}"
            )
            logging.debug("")

        # Assign a type to this block based on the most prevalent type across its IPs
        prevalentType: str = max(types, key=types.get)
        block.setType(prevalentType)

        logging.debug(
            f"Block true size: {block.getTrueSize()}  Block type: {prevalentType}  Type prevalence: {max(types.values()) / block.getTrueSize()}"
        )

    # Dynamic IP Block identification
    # Please refer to the section 4.4 of the paper mentioned above
    # Step 1: Apply median filter method to smooth out dips in IP Usage-Entropy
    logging.info(f"Smoothing IP Usage-Entropy")

    for block in blocks:
        blockIps: list[str] = block.getFullIps()

        # Move a sliding window looking for IP addresses to apply smoothing
        startIdx: int = args.medianFilterWindowSize // 2
        endIdx: int = block.getSize() - args.medianFilterWindowSize // 2

        for idx in range(startIdx, endIdx):
            sliceStartIdx: int = idx - args.medianFilterWindowSize // 2
            sliceEndIdx: int = idx + args.medianFilterWindowSize // 2 + 1

            # If an IP has entropy smaller than threshold, apply smoothing
            # The signal smoothing process can smooth over up to medianFilterWindowSize // 2 consecutive dips
            if combinedEntropy[blockIps[idx]] < args.entropySmoothingThreshold:
                slice: list[str] = blockIps[sliceStartIdx:sliceEndIdx]

                combinedEntropy[blockIps[idx]] = statistics.median(
                    [combinedEntropy[ip] for ip in slice]
                )

    # Step 2: find sub blocks
    # We will sequentially segment the IP_Blocks into smaller segments
    # by discarding the remaining “dips” after signal smoothing
    logging.info(f"Finding sub blocks")

    subBlocks: list[IP_Block] = list()

    for block in blocks:
        subBlocks.extend(findSubBlocks(args, block, combinedEntropy, fingerprintsPerIp))

    logging.info(f"Found {len(subBlocks)} sub blocks")

    # DONE
    # Collect resulting IPs and finish
    allDynamicIps: list[str] = list()
    allProxyIps: list[str] = list()
    allClusterIps: list[str] = list()

    for subBlock in subBlocks:
        match subBlock.type:
            case "dynamic":
                allDynamicIps.extend(subBlock.getFullIps())

            case "proxy":
                allProxyIps.extend(subBlock.getFullIps())

            case "cluster":
                allClusterIps.extend(subBlock.getFullIps())

            case "outlier":
                pass

    logging.info(f"Found {len(allDynamicIps)} total dynamic IP addresses")
    logging.info(f"Found {len(allProxyIps)} total proxy IP addresses")
    logging.info(f"Found {len(allClusterIps)} total cluster IP addresses")

    logging.info(
        f"Total extra IP adresses: {sum(b.getSize() for b in subBlocks) - sum(b.getTrueSize() for b in subBlocks)}"
    )

    return (allDynamicIps, allProxyIps, allClusterIps)


def loadDataFromCache(
    args: argparse.Namespace,
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, IpTimeSeries]]:
    """
    Loads input data from disk if available. Input data needs to be generated by a preprocessing script.

    Also downloads IPASN.dat (for use with pyasn) if not available.

    Parameters
    ----------
    `args`: command line arguments

    Returns
    -------
    A tuple in the following order:
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address
    `ipsPerFingerprint`: a dict of unique IP addresses found per fingerprint
    `ipFingerprintsOverTime`: a dict of a timeseries for each IP address
    """

    fingerprintsPerIp: dict[str, set[str]] = dict()
    ipsPerFingerprint: dict[str, set[str]] = dict()
    ipFingerprintsOverTime: dict[str, IpTimeSeries] = dict()

    # Checking for IPASN.dat cache
    logging.info("Searching for IPASN cache file: IPASN.dat")

    if pathlib.Path(f"{args.cacheFolder}/IPASN.dat").is_file():
        logging.info(f"IPASN cached data found at {args.cacheFolder}/")
    else:
        logging.info(f"IPASN cached data not available at {args.cacheFolder}/")
        logging.info(f"Building IPASN.dat")

        # Step 1: download RIB BGP archives
        res: subprocess.CompletedProcess[bytes] = subprocess.run(
            [
                "pyasn_util_download.py",
                "--latestv4",
                "--filename",
                f"{args.cacheFolder}/rib.latestv4.bz2",
            ]
        )

        if res.returncode != 0:
            logging.error(
                f"Unable to download RIB BGP archives from Routeviews. pyasn_util_download.py exit code: {res.returncode}"
            )
            exit(5)

        # Step 2: convert to IPASN data file
        res: subprocess.CompletedProcess[bytes] = subprocess.run(
            [
                "pyasn_util_convert.py",
                "--single",
                f"{args.cacheFolder}/rib.latestv4.bz2",
                f"{args.cacheFolder}/IPASN.dat",
            ]
        )

        if res.returncode != 0:
            logging.error(
                f"Unable to convert RIB BGP archives to IPASN data file. pyasn_util_convert.py exit code: {res.returncode}"
            )
            exit(5)

        logging.info(f"IPASN cache data has been saved to {args.cacheFolder}/")

    # Checking for input data
    filenameFPI: str = f"{args.cacheFolder}/FPI.pickle"
    filenameIPF: str = f"{args.cacheFolder}/IPF.pickle"
    filenameIFOT: str = f"{args.cacheFolder}/IFOT.pickle"

    logging.info(
        f"Searching for DynMap input files: {filenameFPI}, {filenameIPF}, {filenameIFOT}"
    )

    cacheIsAvailable: bool = (
        pathlib.Path(filenameFPI).is_file()
        and pathlib.Path(filenameIPF).is_file()
        and pathlib.Path(filenameIFOT).is_file()
    )

    if cacheIsAvailable:
        logging.info(f"Input data found at {args.cacheFolder}/")
        logging.info("Loading cached data")

        fingerprintsPerIp = pickle.load(open(filenameFPI, "rb"))
        ipsPerFingerprint = pickle.load(open(filenameIPF, "rb"))
        ipFingerprintsOverTime = pickle.load(open(filenameIFOT, "rb"))
    else:
        logging.error(f"Input data not available at {args.cacheFolder}/")

        logging.info(f"Please preprocess your data source first.")
        exit(0)

    return (fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime)


def validateArgs(args: argparse.Namespace) -> None:
    """
    Validates command line arguments.

    Exits if any argument is invalid.

    Parameters
    ----------
    `args`: command line arguments
    """

    if args.minBlockSize < 4:
        logging.error(f"Min block size cannot be less than 4")
        exit(4)

    if args.maxGapSize < 0 or args.maxGapSize > args.minBlockSize:
        logging.error(
            f"Max gap size cannot be greater than min block size or less than zero"
        )
        exit(4)

    if args.entropySmoothingThreshold < 0.0 or args.entropySmoothingThreshold > 1.0:
        logging.error(
            f"Entropy smoothing threshold should be in the interval [0.0, 1.0]"
        )
        exit(4)

    if (
        args.medianFilterWindowSize < 1
        or args.medianFilterWindowSize % 2 == 0
        or args.medianFilterWindowSize > args.minBlockSize
    ):
        logging.error(
            f"Median filter window size should be odd and between [1, minBlockSize]"
        )
        exit(4)

    # Feedback
    logging.info("Starting DynMap")
    logging.info("Selected parameters:")
    logging.info(f"Min block size: {args.minBlockSize}")
    logging.info(f"Max gap size: {args.maxGapSize}")
    logging.info(f"Entropy smoothing threshold: {args.entropySmoothingThreshold}")
    logging.info(f"Median filter window size: {args.medianFilterWindowSize}")


# Start here
if __name__ == "__main__":
    # Get args
    parser = initParser()
    args = parser.parse_args()

    # Auto enable log file if log level is DEBUG
    if args.loglevel == "DEBUG" and args.logfile == None:
        args.logfile = f"dynmap_debug.log"
        print(
            f"A log file is required for log level DEBUG. Logs will be written to '{args.logfile}'"
        )

    # Set up log
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=getattr(logging, args.loglevel),
        filename=args.logfile,
        encoding="utf-8",
    )

    validateArgs(args)

    # Step 1: Get fingerprints per IP address and IP addresses per fingerprint
    (fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime) = loadDataFromCache(
        args
    )

    # Step 2: Apply rules to filter out dynamic ips
    logging.info("Starting analysis")

    dynamicIps, proxyIps, clusterIps = findDynamicIps(
        args, fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime
    )

    # Step 3: Save results to a .pickle file
    if args.shouldSaveIps:
        dynamicIps.sort()
        proxyIps.sort()
        clusterIps.sort()

        filename: str = f"dynmap_b{args.minBlockSize}_g{args.maxGapSize}_t{args.entropySmoothingThreshold}_w{args.medianFilterWindowSize}"

        outputData: dict[str, Any] = {
            "min_block_size": args.minBlockSize,
            "max_gap_size": args.maxGapSize,
            "smoothing_threshold": args.entropySmoothingThreshold,
            "median_window_size": args.medianFilterWindowSize,
            "total_input_ips": len(fingerprintsPerIp),
            "total_output_ips": len(dynamicIps) + len(proxyIps) + len(clusterIps),
            "dynamic_ips": dynamicIps,
            "proxy_ips": proxyIps,
            "cluster_ips": clusterIps,
        }

        pickle.dump(outputData, open(f"{filename}.pickle", "wb"))

        logging.info(
            f"Total dynamic/proxy/cluster IP addresses have been written to {filename}.pickle"
        )
