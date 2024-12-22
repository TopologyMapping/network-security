"""
This file contains all the constants to use in the classification task.

The idea is to classify each file in two dimensions:
    1: what is detected
    vulnerability, unmaintained software, property of a system
    2: how is detected
    simulated attack, privileged scan, basic active requests (and their subcategories)

For each possible action performed by a scanner, is defined a specific prompt, directing the AI to the correct classification, and excluding the other possibilities.

All the prompts used were defined through the analysis of the scripts and experimentation. 
"""

FILE_EXTENSION_OPENVAS = ".nasl"
FILE_EXTENSION_NUCLEI = ".yaml"
FILE_EXTENSION_NMAP = ".nse"

SYSTEM_PROMPT = "You are a world-class AI system, capable of complex reasoning and reflection. Reason through the query inside <thinking> tags, and then provide your final response inside <output> tags. If you detect that you made a mistake in your reasoning at any point, correct yourself inside <reflection> tags."

# qod values for OpenVAS - https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#quality-of-detection-concept
QOD_VALUE = {
    "exploit": 100,
    "remote_vul": 99,
    "remote_app": 98,
    "package": 97,
    "registry": 97,
    "remote_active": 95,
    "remote_banner": 80,
    "executable_version": 80,
    "default": 75,
    "remote_analysis": 70,
    "remote_probe": 50,
    "remote_banner_unreliable": 30,
    "executable_version_unreliable": 30,
    "general_note": 1,
    "timeout": 0,
}


PROMPT_WHAT_IS_DETECTED_ATTACK = """ 
1.1 Vulnerability: A script can perform a series of actions to detect a vulnerability or a set of vulnerabilities. In most cases a vulnerability is identified by a CVE number, and impacts a set of products identified by CPE numbers. But a vulnerability could be configurations problems on the machine, without a CVE number, allowing bad behaviours.  For scripts that scan a vulnerability, please find: (A) the application under test, which contains the vulnerability or flaw; this may be referred to in the description of the script but not clear from the script’s code. (B) the version of the application being tested, (C) the intermediary application or service, if any, used to exploit the vulnerability; this can be inferred by looking at any request being constructed, look at the contents of the request, its inputs, and where it is sent.

To complete this task, analyze the detection script code, metadata, comments and verifications to find what is detected, the application, specific targets, and other necessary information. If you cannot find one of the required information, just answer with "Uncertain".

Please fill out the template below. Change only the sections within curly braces, keep the braces on the response, and follow the intructions within the braces considering the explanation above:

What is detected: {select one of Vulnerability, Unmaintained Software, or Property of a System, as described above and answer directly}
A: {answer to subitem (A) of what is detected}
B: {answer to subitem (B) of what is detected}
C: {answer to subitem (C) of what is detected}
"""

PROMPT_WHAT_IS_DETECTED = """ 
1.1 Vulnerability: A script can perform a series of actions to detect a vulnerability or a set of vulnerabilities. In most cases a vulnerability is identified by a CVE number, and impacts a set of products identified by CPE numbers. But a vulnerability could be configurations problems on the machine, without a CVE number, allowing bad behaviours.  For scripts that scan a vulnerability, please find: (A) the application under test, (B) the version of the application that is targeted by the script.

1.2 Old Software: Software that is old may no longer receive security updates. As such, these software put systems at higher risk even if there are no known vulnerabilities. Scripts can detect these unmaintained software by checking for end-of-life periods or whether libraries or frameworks have been deprecated. Another case in this category is software that has not received updates that correct security problems. For scripts that identify unmaintained software, please find: (A) the software identified as unmaintained or old software (this can be either an application, package, library, or framework); (B) the version of the software that is searched for, or classified as unmaintained.

1.3 Properties of a System: Scripts may identify properties of a system. Although properties of a system are not vulnerabilities, they can be used by malicious actors to obtain information about the system. For scripts that identify properties of a system, please find: (A) a one-phrase description of the property being identified; (B) the value of the identified property, if applicable.

To complete this task, analyze the detection script code, metadata, comments and verifications to find what is detected, the application, specific targets, and other necessary information. If you cannot find one of the required information, just answer with "Uncertain".

Please fill out the template below. Change only the sections within curly braces, keep the braces on the response, and follow the intructions within the braces considering the explanation above:

What is detected: {select one of Vulnerability, Unmaintained Software, or Property of a System, as described above and answer directly}
A: {answer to subitem (A) of what is detected}
B: {answer to subitem (B) of what is detected}
"""

CATEGORIES_ATTACK = """
1. Category: Simulated Attack. Description: The script runs tests that simulate real attacks or perform attack-like behaviors, confirming the existence of the vulnerability, performing active probes, including parameters on the URL or making specific and detailed requests to collect information about the target machine.

1.1. Subcategory: External Code Execution. Description: Attempts to execute code or a payload on the target machine from an external connection. If the code attempts to perform malicious actions, inject code on the target, gain access over the target, performs buffer overflow or just tests whether it is possible to execute remote code, then it falls into this category.
1.2. Subcategory: Unauthorized Login. Description: Tries to access a running service by guessing potential credentials (like brute force) or hijacking an authenticated user session.
1.3. Subcategory: Protected Information. Description: Attempts to access restricted files, reveal sensitive information, change system settings or machine parameters or gain privileged access that should be protected and inaccessible to unauthorized users.
1.4. Subcategory: Denial of Service (DoS). Description: Attempts to disrupt or overload a service, making it unavailable to legitimate users.
1.5. Subcategory: Privileged Attack. Description: Attempts to exploit vulnerabilities with memory manipulation, payloads or remote code execution through credentials provided by the user in the tool parameters. If the code has as parameters, access credentials necessary for its operation then it falls into this category.
"""

CATEGORIES_PRIVILEGED = """
2. Category: Privileged Scan. Description: Performs scans with privileged information, like (i) credentials provided by the user to specific services, (ii) when running inside the target machine directly or (iii) runs the tests with privileged permissions or access. The script may run internal commands and gather detailed info about installed packages and configurations.

2.1. Subcategory: Package List. Description: Extracts the list of installed packages to check the versions of running services and correlate them with known vulnerabilities. If the code looks for some application or service in a list or registry of installed packages, then it falls into that subcategory.
2.2. Subcategory: Service information. Description: Reviews the configuration of services, files, and security policies to identify misconfigurations that could expose the system to risks or collect information about the target machine.
2.3. Subcategory: Log File Analysis. Description: Analyzes system logs for suspicious activity, potential security incidents, or errors that could indicate misconfigurations or breaches.
"""

CATEGORIES_BASIC_REQUEST = """
3. Category: Basic Active Requests. Description: The script gathers information by making simple requests or observing data that the target system passively exposes such as responde banners with software version, configuration details, URLs or open services. The test does not require authentication, perform any intrusive actions, authentication attempts, attack simulations, nor crafts specific packets for requests.

3.1. Subcategory: Banner Check. Description: Checks software information, application version, HTTP status code or the running service based on the initial response (banner) sent by the server after basic interaction from the scanner. Returns inferred vulnerabilities or the information collected just sendind simple requests and checking elements of the response. If a code performs a request and just check the response once, then enters in this subcategory.
3.2. Subcategory: URL Presence Check. Description: Identifies the vulnerabilities checking if exists vulnerable URLs or paths on the target. The tested URL is present in the code and represents the vulnerability. The URL is not provided by the user as a parameter for executing the script. If the vulnerability is detected by the presence of the URL, then the code falls into this category.
3.3. Subcategory: Discovery. Description: Executes other actions to test the existence of the vulnerability without actually exploiting it, or performs active probing to just collect information about the target machine.
"""

PROMPT_CATEGORIES = """
To complete this task, analyze the detection script code, metadata, comments and verifications to find how the detection is made. First identify the category of a script, and then the subcategory. Please, to answer the question, fill out the template below. Change only the sections within curly braces, keep the braces on the response, and follow the intructions within the braces considering the explanation above:

How the script works?
Category: {Category}
Subcategory: {Subcategory}
Explanations: {explanation about the code}

If a subcategory matches the script, please simply report the number of the subcategory and do not provide any additional explanation. If no match is found, please propose and describe a new category or subcategory.

Think carefully.
"""

######### METASPLOIT ##################

PROMPT_METASPLOIT_POST = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """
#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_PRIVILEGED
    + PROMPT_CATEGORIES
)


PROMPT_METASPLOIT_NOT_EXPLOIT_NOT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Auxiliary modules 
Module description: Auxiliary modules do not exploit a target, but can perform useful tasks such as:

Administration - Modify, operate, or manipulate something on target machine
Analyzing - Tools that perform analysis, mostly password cracking
Gathering - Gather, collect, or enumerate data from a single target
Denial of Service - Crash or slow a target machine or service
Scanning - Scan targets for known vulnerabilities
Server Support - Run Servers for common protocols such as SMB, FTP, etc

=====

Module name: Encoder modules
Module description: Encoders take the raw bytes of a payload and run some sort of encoding algorithm, like bitwise XOR. These modules are useful for encoding bad characters such as null bytes.

=====

Module name: Evasion modules 
Module description: Evasion modules give Framework users the ability to generate evasive payloads that aim to evade AntiVirus, such as Windows Defender, without having to install external tools.

=====

Module name: Nop modules
Module description: Nop modules, short for ‘No Operation’, generate a sequence of ‘No Operation’ instructions that perform no side-effects. NOPs are often used in conjunction with stack buffer overflows.

=====

Module name: Payloads modules 
Module description: In the context of Metasploit exploit modules, payload modules encapsulate the arbitrary code (shellcode) that is executed as the result of an exploit succeeding. This normally involves the creation of a Metasploit session, but may instead execute code such as adding user accounts, or executing a simple pingback command that verifies that code execution was successful against a vulnerable target.

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """
#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_BASIC_REQUEST
    + PROMPT_CATEGORIES
)


PROMPT_METASPLOIT_EXPLOIT = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
    + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + PROMPT_CATEGORIES
)

PROMPT_METASPLOIT_EXPLOIT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
)


PROMPT_METASPLOIT_PRIVILEGED = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Metasploit application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about Metasploit's Modules. Each Metasploit files has a module identification, with each identification representing some behavior about the code. This will be helpfull to analyze the codes presented. We precede each Module information and separate them using the special "=====" string:

=====

Module name: Auxiliary modules 
Module description: Auxiliary modules do not exploit a target, but can perform useful tasks such as:

Administration - Modify, operate, or manipulate something on target machine
Analyzing - Tools that perform analysis, mostly password cracking
Gathering - Gather, collect, or enumerate data from a single target
Denial of Service - Crash or slow a target machine or service
Scanning - Scan targets for known vulnerabilities
Server Support - Run Servers for common protocols such as SMB, FTP, etc

=====

Module name: Encoder modules
Module description: Encoders take the raw bytes of a payload and run some sort of encoding algorithm, like bitwise XOR. These modules are useful for encoding bad characters such as null bytes.

=====

Module name: Evasion modules 
Module description: Evasion modules give Framework users the ability to generate evasive payloads that aim to evade AntiVirus, such as Windows Defender, without having to install external tools.

=====

Module name: Exploit modules
Module description: Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code. The arbitrary code that is executed is referred to as the payload.

=====

Module name: Nop modules
Module description: Nop modules, short for ‘No Operation’, generate a sequence of ‘No Operation’ instructions that perform no side-effects. NOPs are often used in conjunction with stack buffer overflows.

=====

Module name: Payloads modules 
Module description: In the context of Metasploit exploit modules, payload modules encapsulate the arbitrary code (shellcode) that is executed as the result of an exploit succeeding. This normally involves the creation of a Metasploit session, but may instead execute code such as adding user accounts, or executing a simple pingback command that verifies that code execution was successful against a vulnerable target.

=====

Module name: Post modules
Module description: These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful tasks such as gathering, collecting, or enumerating data from a session.

=====

#####

Futhermore, is presented information about Metasploit ranking, representing a category received by each script that describes the behavior of Exploit modules. Again, the content is separated by '====='. Below is presented the ranking name and the description.

=====

Ranking name: ExcellentRanking	

Ranking description: The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()).

=====

Ranking name: GreatRanking	

Ranking description: The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check.
GoodRanking	The exploit has a default target and it is the “common case” for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). Exploit does not auto-detect the target.

=====

Ranking name: NormalRanking	

Ranking description: The exploit is otherwise reliable, but depends on a specific version that is not the “common case” for this type of software and can’t (or doesn’t) reliably autodetect.
AverageRanking	The exploit is generally unreliable or difficult to exploit, but has a success rate of 50% or more for common platforms.

=====

Ranking name: LowRanking	

Ranking description: The exploit is nearly impossible to exploit (under 50% success rate) for common platforms.

=====

Ranking name: ManualRanking	

Ranking description: The exploit is unstable or difficult to exploit and is basically a DoS (15% success rate or lower). This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).

=====

#####

Task 1: Identify **what** an Metasploit script detects

An Metasploit script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Metasploit script works

An Metasploit script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + PROMPT_CATEGORIES
)

######### NUCLEI ##################

PROMPT_NUCLEI = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

An Nuclei template can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Nuclei template works

An Nuclei template can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + CATEGORIES_PRIVILEGED
    + CATEGORIES_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_NUCLEI_REMOTE_CODE_EXECUTION = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
)

PROMPT_NUCLEI_AUTH_BYPASS = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nuclei application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nuclei template detects

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
)

######### NMAP ##################

PROMPT_NMAP = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an Nmap script works

An Nmap script can work in many different ways. Pay attention in required arguments that , if exists, could indicate privileged information needed by the scan. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + CATEGORIES_PRIVILEGED
    + CATEGORIES_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_NMAP_BRUTE_DOS = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
)

PROMPT_NMAP_DISCOVERY = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
)

PROMPT_NMAP_ATTACK = (
    """ 
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the Nmap application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Task 1: Identify **what** an Nmap script detects

An Nmap script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
    + """

#####

Task 2: Identify **how** an Nmap script works

An Nmap script can work in many different ways. Pay attention in required arguments that , if exists, could indicate privileged information needed by the scan. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + PROMPT_CATEGORIES
)

########## OPENVAS ##################

PROMPT_OPENVAS_NOT_EXPLOIT_NOT_AUTHENTICATED = (
    """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:

=====
QOD Value: 99%
QOD Name: Remote Vulnerability
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerability.

=====
QOD Value: 98%
QOD Name: Remote Application
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerable application.

=====

QOD Value: 95%
QOD Name: Remote Active
Description: Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response shows the likely presence of the vulnerable application or of the vulnerability. "Likely" means that only rare circumstances are possible in which the detection would be wrong.

=====
QOD Value: 80%
QOD Name: Remote Banner
Description: Remote banner checks of applications that offer patch level in version. Many proprietary products do so.

=====
QOD Value: 80 %
QOD Name: Executable Version
Description: Authenticated executable version checks for Linux(oid) or Microsoft Windows systems where applications offer patch level in version.

=====
QOD Value: 30 %
QOD Name: Executable Version Unreliable
Description: Authenticated executable version checks for Linux(oid) systems where applications do not offer patch level in version identification.

=====
QOD Value: 1 %
QOD Name: General Note
Description: General note on potential vulnerability without finding any present application.

=====
QOD Value: 0 %
QOD Name: Timeout
Description: The test was unable to determine a result before it was ended by timeout.

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_BASIC_REQUEST
    + PROMPT_CATEGORIES
)

PROMPT_OPENVAS_EXPLOIT = (
    """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:

=====
QOD Value: 100%
QOD Name: Exploit
Description: The detection happened via an exploit and is therefore fully verified.

=====

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED_ATTACK
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_ATTACK
    + PROMPT_CATEGORIES
)

PROMPT_OPENVAS_AUTHENTICATED = (
    """     
            
You are a cibersecurity expert. In this task we will analyze vulnerability detection scripts from the OpenVAS application to understand how they work. This document is structured in sections separated by the special "#####" string.

#####

Below is some reference information about OpenVAS's Quality of Detection (QOD) metric.  Each detection script has an associated QOD metric. The QOD varies from 0 to 100 and indicates how confident OpenVAS is that a vulnerability exists if the script reports a vulnerability. Below we list all possible QODs, specifying their values, names, and description. We precede each QOD and separate them using the special "=====" string:


=====
QOD Value: 97%
QOD Name: Package
Description: Authenticated package-based checks for Linux(oid) systems. This category refers to authenticated scans.

=====
QOD Value: 97%
QOD Name: Registry
Description: Authenticated registry based checks for Microsoft Windows systems. This category refers to authenticated scans.

=====

#####

Task 1: Identify **what** an OpenVAS script detects

An OpenVAS script can detect one of three things:

"""
    + PROMPT_WHAT_IS_DETECTED
    + """

#####

Task 2: Identify **how** an OpenVAS script works

An OpenVAS script can work in many different ways. We want to classify how a script works following the following categories and subcategories:

"""
    + CATEGORIES_PRIVILEGED
    + PROMPT_CATEGORIES
)

# one of the tasks executed in this module is to group similar files. The prompt below is used to answer this task using the LLM.

PROMPT_COMPARE_SIMILARITY = """
    You are an expert on cybersecurity tools. Below are two OpenVAS vulnerability detection scripts, implemented in OpenVAS's NASL language, separated by “=====”. The scripts perform actions to check the existence of a vulnerability on the target host. 

    Based on analyzing the script's metadata and code, please provide answers to the two questions below. 

    Question 1: Are the scripts similar? yes or no?
    Question 2: Please explain your answer to question 1 in one phrase.

    Output only two lines, with the answer to the first question on the first line and the answer to the second question on the second line. Return the answer inside the following structure. Do not add any more information outside the following structure and pattern -> Answer1: [ answer about similarity (yes or no) ] Answer2: [ explanation about similarity answer ]. Mantain the words 'Answer1' and 'Answer2' on the answer. Below are two example outputs separated by '-----':

    Answer1: yes
    Answer2: The scripts are similar because they perform the same actions to detect the same vulnerability

    '-----'

    Answer1: no
    Answer2: The scripts are not similar because one verifies a banner response and the other realizes an exploit crafting packages

    Consider that two scripts are similar if they perform the same overall actions, but allow for slight differences. Examples:

    A script that looks at the set of installed packages on Debian to identify a vulnerable version of Apache IS similar to a script that looks at the set of installed packages on Suse, or any other distribution, to identify the same vulnerable version of Apache.

    A script that tests a vulnerability through application A, and another that tests the same vulnerability in the same way but in application B are NOT similar.

    A script that looks at the set of installed packages on Debian to identify a vulnerable version of Apache is NOT similar to a script that inspects the Windows registry (or installed programs) for the same vulnerable version of Apache.

    A script that looks at the set of installed packages on Debian to identify a vulnerable version of Apache is NOT similar to a script that issues an HTTP request to check if the server is running the same vulnerable version of Apache.

    More generally, if the scripts employ different vulnerability detection methods (e.g., checking installed packages, issuing HTTP requests, performing an exploit, attempting an unauthorized login), then they are NOT similar. The metadata in a script may also be useful to identify its mode of operation and whether two scripts are similar.
    """