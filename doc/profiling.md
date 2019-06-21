# Profiling

There is a Vagrantfile with performance inspection tools like SystemTap.

```shell
vagrant up
vagrant ssh
```

APIcast is mounted into `/home/vagrant/app` so you can start it by:

```shell
cd app
bin/apicast
```

For profiling with stapxx it is recommended to start just one process and worker:

```shell
bin/apicast -c examples/configuration/echo.json  > /dev/null
```

Then by opening another terminal you can use vegeta to create traffic:

```shell
echo 'GET http://localhost:8080/?user_key=foo' | vegeta attack -rate=200 -duration=5m | vegeta report
```

Or you can use wrk to get as much throughtput as possible:

```shell
wrk --connections 100 --threads 10 --duration 300 'http://localhost:8080/?user_key=foo'
```

And in another terminal you can create flamegraphs:

```shell
lj-lua-stacks.sxx  -x `pgrep -f 'nginx: worker'` --skip-badvars --arg time=10 | fix-lua-bt - | stackcollapse-stap.pl | flamegraph.pl > /vagrant/graph.svg
```
