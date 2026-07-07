event eCacheDown: machine;
event eCacheHealth: (who: machine, healthy: int);
event eMetricChanged: int;

spec MetricEventuallyConverges observes eCacheDown, eCacheHealth, eMetricChanged {
    // every cache currently up (any health)
    var up: set[machine];
    // the up caches reporting healthy
    var healthyUp: set[machine];
    var metric: int;

    start cold state Init {
        entry {
            goto Converged;
        }
    }

    cold state Converged {
        on eCacheHealth do (r: (who: machine, healthy: int)) {
            up += (r.who);
            if (r.healthy == 1) {
                healthyUp += (r.who);
            } else {
                healthyUp -= (r.who);
            }
            check();
        }

        on eCacheDown do (who: machine) {
            up -= (who);
            healthyUp -= (who);
            check();
        }

        on eMetricChanged do (h: int) {
            metric = h;
            check();
        }
    }

    hot state Diverged {
        on eCacheHealth do (r: (who: machine, healthy: int)) {
            up += (r.who);
            if (r.healthy == 1) {
                healthyUp += (r.who);
            } else {
                healthyUp -= (r.who);
            }
            check();
        }

        on eCacheDown do (who: machine) {
            up -= (who);
            healthyUp -= (who);
            check();
        }

        on eMetricChanged do (h: int) {
            metric = h;
            check();
        }
    }

    fun check() {
        if (metric == expected()) {
            goto Converged;
        } else {
            goto Diverged;
        }
    }

    fun expected(): int {
        if (sizeof(up) == 0 || sizeof(healthyUp) > 0) {
            return 1;
        } else {
            return 0;
        }
    }
}
