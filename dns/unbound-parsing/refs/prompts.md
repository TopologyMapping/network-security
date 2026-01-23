we want to analyze the unbound logs in /home/datasets/dnssync.  the unbound logs compressed with gzip and anonymized (hiding the IP address of the client using a prefix-preserving anonymization scheme).

please write rust code to load the unbound logs python code to load the unbound logs, and then generate text files (e.g., csv) that we will then feed to python scripts using matplotlib to plot graphs.

we want to build the graphs below.  the rust code must generate the text files needed to feed the graphs.

1. One graph showing timeseries of (i) the number of DNS requests received per hour by the unbound server; (ii) number of distinct clients seen at the server per hour (the sources are anonymized, but we can still count them just fine); (iii) number of distinct FQDNs resolved by the unbound server per hour

2. for each week, plot a log-log graph showing the number of times each FQDN was resolved on the Y axis, and the rank of the FQDNs on the X axis (sorting FQDNs by number of occurrences). this should result in a zipf-like distribution.  add labels to the top 10 points in the graph to denote the corresponding FQDNs.

-----

1. all hours, create one graph per week. make the graph 16:9 ratio so it looks better.

2. start weeks on mondays.

3. no specific style for the graphs.  add labels to the axes.

4. add the week identifier (days covered) as the title of each graph.

-----

1. the time series graphs seem to have a problem. the number of distinct FQDNs seems higher than the number of requests, which is impossible. please troubleshoot.

2. please make sure all timeseries graphs start on a Monday, and end on the next Monday

3. Please write the labels on the Zipf distribution graphs vertically, below each point, this should ease readability
