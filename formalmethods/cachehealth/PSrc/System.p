event eReport: (who: machine, healthy: int);
event eStop;
event eDeregister: machine;
event eSetHealth: int;

machine MetricBug {
    var healthy: int;

    start state Reporting {
        entry {
            healthy = 0;
        }

        on eReport do (r: (who: machine, healthy: int)) {
            healthy = r.healthy;
            announce eMetricChanged, healthy;
        }

        ignore eDeregister;
    }
}

machine Metric {
    var health: map[machine, int];

    start state Init {
        entry {
            goto Reporting;
        }
    }

    state Reporting {
        on eReport do (r: (who: machine, healthy: int)) {
            health[r.who] = r.healthy;
            announce eMetricChanged, anyHealthy();
        }

        on eDeregister do (who: machine) {
            health -= who;
            announce eMetricChanged, anyHealthy();
        }
    }

    fun anyHealthy(): int {
        var k: machine;

        // If no cache is up, report healthy. This is a valid state and
        // alternative to deleting this metric.
        if (sizeof(health) == 0) {
            return 1;
        }

        // If any cache is is healthy, report healthy status.
        foreach (k in keys(health)) {
            if (health[k] == 1) {
                return 0;
            }
        }

        // If nothing is healthy, then report unhealthy.
        return 0;
    }
}

machine Cache {
    var metric: machine;

    start state Init {
        entry (m: machine) {
            metric = m;
            goto Healthy;
        }
    }

    state Healthy {
        entry {
            send metric, eReport, (who = this, healthy = 1);
            announce eCacheHealth, (who = this, healthy = 1);
        }

        on eSetHealth do (healthy: int) {
            if (healthy == 0) {
                goto Unhealthy;
            }
        }

        on eStop do {
            goto Stopped;
        }
    }

    state Unhealthy {
        entry {
            send metric, eReport, (who = this, healthy = 0);
            announce eCacheHealth, (who = this, healthy = 0);
        }

        on eSetHealth do (healthy: int) {
            if (healthy == 1) {
                goto Healthy;
            }
        }

        on eStop do {
            goto Stopped;
        }
    }

    state Stopped {
        entry {
            send metric, eDeregister, this;
            announce eCacheDown, this;
        }

        ignore eStop;
        ignore eSetHealth;
    }
}
