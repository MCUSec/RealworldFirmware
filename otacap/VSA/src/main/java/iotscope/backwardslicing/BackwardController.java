package iotscope.backwardslicing;

import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.ValuePoint;
import iotscope.main.Config;
import iotscope.utility.TimeWatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class BackwardController {
    private static final Logger LOGGER = LoggerFactory.getLogger(BackwardController.class);

    private final static BackwardController BACKWARD_CONTROLLER = new BackwardController();

    private TimeWatcher timeWatcher = TimeWatcher.getTimeWatcher();

    public static BackwardController getInstance() {
        return BACKWARD_CONTROLLER;
    }

    private BackwardController() {

    }

    /**
     * Go backward until the all result contexts have finished
     *
     * @param valuePoint to perform backward search
     * @param dataGraph  for backward tracing
     * @return All backward Context
     */
    public List<BackwardContext> doBackWard(ValuePoint valuePoint, DataDependenciesGraph dataGraph) {
        List<BackwardContext> resultContexts = new ArrayList<>();
        resultContexts.add(new BackwardContext(valuePoint, dataGraph));
        while (true) {
            BackwardContext backwardContext = null;
            for (BackwardContext tmp : resultContexts) {
                if (!tmp.backWardHasFinished()) {
                    backwardContext = tmp;
                    break;
                }
            }
            if (backwardContext == null || timeWatcher.getTimeoutBackwardIsUp()) {
                if (timeWatcher.getTimeoutBackwardIsUp()) {
                    timeWatcher.markTimeoutBackwardUsed();
                }
                break;
            }
            List<BackwardContext> tmp = backwardContext.oneStepBackWard();
            if (resultContexts.size() < Config.MAXBACKWARDCONTEXT) {
                resultContexts.addAll(tmp);
                if (backwardContext.getBackwardContextToAdd() != null && backwardContext.getBackwardContextToAdd().size()>0) {
                    resultContexts.addAll(backwardContext.getBackwardContextToAdd());
                    backwardContext.resetBackwardContextToAdd();
                }
            }
        }

        LOGGER.info("Backward done for ValuePoint: {} Logging Execution Traces from Contexts:\n---------------------------------------", valuePoint);
        resultContexts.forEach(BackwardContext::logExecTrace);

        return resultContexts;

    }

}
