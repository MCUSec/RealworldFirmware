package iotscope.utility;

import iotscope.main.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TimeWatcher to stop the execution if it runs out of the configured time
 */
public class TimeWatcher implements Runnable {
    private static final Logger LOGGER = LoggerFactory.getLogger(TimeWatcher.class);

    private boolean timeoutBackwardIsUp = false;
    //flags that the timeout was used
    private boolean timeoutBackwardUsed = false;

    private boolean timeoutForwardIsUp = false;
    //flags that the timeout was used
    private boolean timeoutForwardUsed = false;

    private boolean timeoutSymbolicIsUp = false;

    private boolean timeoutSymbolicUsed = false;

    private boolean shouldContinue = false;

    private final static TimeWatcher TIME_WATCHER = new TimeWatcher();

    public static TimeWatcher getTimeWatcher() {
        return TIME_WATCHER;
    }

    private TimeWatcher() {

    }

    @Override
    public void run() {
        try {
            Thread.sleep(Config.TIMEOUT_BACKWARDS * 1000L);
            //give application time to clean up and write out results
            timeoutBackwardIsUp = true;
            Thread.sleep(Config.TIMEOUT_FORWARD * 1000L);
            timeoutForwardIsUp = true;

            Thread.sleep(Config.TIMEOUT_FORWARD * 1000L);
            timeoutSymbolicIsUp = true;
            // 15 minute for cleaning up
            Thread.sleep( 15* 1000L);

        } catch (InterruptedException e) {
            LOGGER.debug("Thread got interrupted");
        }
    }

    public void continueMeasurement() {
        shouldContinue = true;
    }

    public boolean getTimeoutBackwardIsUp() {
        return timeoutBackwardIsUp;
    }

    public void markTimeoutBackwardUsed() {
        timeoutBackwardUsed = true;
    }

    public boolean getTimeoutForwardIsUP() {
        return timeoutForwardIsUp;
    }

    public void markTimeoutForwardUsed() {
        timeoutForwardUsed = true;
    }

    public boolean isTimeoutBackwardUsed() {
        return timeoutBackwardUsed;
    }

    public boolean isTimeoutForwardUsed() {
        return timeoutForwardUsed;
    }

    public boolean getTimeoutSymbolicIsUp() {
        return timeoutSymbolicIsUp;
    }

    public void markTimeoutSymbolicUsed() {
        timeoutSymbolicUsed = true;
    }

    public boolean getTimeoutSymbolicUsed() {
        return timeoutSymbolicUsed;
    }

    public void markTimeoutSymbolicIsUp() {
        timeoutSymbolicIsUp = true;
    }

    public boolean isTimeoutSymbolicUsed() {
        return timeoutSymbolicUsed;
    }
}
