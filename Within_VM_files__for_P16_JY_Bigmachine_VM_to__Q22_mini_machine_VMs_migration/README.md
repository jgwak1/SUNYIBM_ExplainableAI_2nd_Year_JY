disable concurrency with logstash.yml (worker =1 , batch size =1 )
to minimize streaming-overhead by only streaming out events generated by splunkd descendent process pids by dynamically identifyinng them.