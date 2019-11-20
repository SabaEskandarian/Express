
This code accompanies our upcoming paper on metadata-hiding communication. A link will be added here when the paper is available. 

#### Usage
```
client [serverAip:4443] [serverBip:4442] [numThreads] [rowDataSize] (optional)throughput

serverA [serverBip:4442] [numThreads] [numCores (set it to 0)] [numRows] [rowDataSize]

serverB [numThreads] [numCores (set it to 0)] [numRows] [rowDataSize]

```

* The port numbers shown above are required by the implementation, but this should be easy to change if you want to run the system on another port. 

* `numThreads` tells the system how many worker goroutines to create. We set this to 1x or 2x the number of cores on the system for our evaluation. 

* `numCores` is not used but must be set to 0 or it will hurt performance. 

* `NumRows` tells the servers how many dummy rows to put in the database after one initial row is set up by the client. So to evaluate on 1,000 rows, this value would be set to 999.

* `rowDataSize` sets the size of rows, in bytes

* By default, the client runs a write followed by a read several times in a row and reports the average as well as the client computation time for each write (the first write/read are slowed down by the setup process and omitted from the average). To measure throughput instead, add the word `throughput` as an additional argument to `client`. This will cause the client to send `numThreads` requests in parallel as fast as it can (set `numThreads` larger than the actual number of cores on the machine). `serverA` will report the total elapsed time and total number of writes processed every 10 seconds after setup. 

#### Notes

The data from our experiments can be found in the `data/` folder. Feel free to get in touch for help in running the system or using it in your own evaluations. 

The dpf implementation is partially based on weikengchen/libdpf.

#### Important Warning

DO NOT USE THIS SOFTWARE TO SECURE ANY SORT OF
REAL-WORLD COMMUNICATIONS!

This software is for performance testing ONLY!
It is full of security vulnerabilities that could
be exploited in any real-world deployment.

The purpose of this software is to evaluate
the performance of the system, NOT to be
used in a deployment scenario.
