package iotscope.symbolicsimulation;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.SValuePoint;
import iotscope.main.Config;
import iotscope.utility.TimeWatcher;

public class SymbolicController {

    private TimeWatcher timeWatcher = TimeWatcher.getTimeWatcher();
    
    private static final Logger LOGGER = LoggerFactory.getLogger(SymbolicController.class);

    private final static SymbolicController SYMBOLIC_CONTROLLER = new SymbolicController();

    public static SymbolicController getInstance() {
        return SYMBOLIC_CONTROLLER;
    }

    private SymbolicController() {

    }

    public List<SymbolicContext> doForward(SValuePoint valuePoint, DataDependenciesGraph dataGraph) {
        List<SymbolicContext> resultContexts = new ArrayList<>();
        resultContexts.add(new SymbolicContext(valuePoint, dataGraph));
        while (true) {
            SymbolicContext symbolicContext = null;
            for (SymbolicContext tmp : resultContexts) {
                if (!tmp.symbolicHasFinished()) {
                    symbolicContext = tmp;
                    break;
                }
            }
            // TODO: change to symbolic specific values
            if (symbolicContext == null || timeWatcher.getTimeoutSymbolicIsUp()) {
                if (timeWatcher.getTimeoutSymbolicIsUp()) {
                    timeWatcher.markTimeoutSymbolicUsed();
                }
                break;
            }
            List<SymbolicContext> tmp = symbolicContext.oneStepForward();
            if (resultContexts.size() < Config.MAXSYMCONTEXT) {
                resultContexts.addAll(tmp);
                if (symbolicContext.getSymbolicContextToAdd() != null && symbolicContext.getSymbolicContextToAdd().size()>0) {
                    resultContexts.addAll(symbolicContext.getSymbolicContextToAdd());
                    symbolicContext.resetSymbolicContextToAdd();
                }
            }
        }

        LOGGER.info("Symbolic done for ValuePoint: {} Logging Execution Traces from Contexts:\n---------------------------------------", valuePoint);
        resultContexts.forEach(SymbolicContext::logExecTrace);

        return resultContexts;
    }

}