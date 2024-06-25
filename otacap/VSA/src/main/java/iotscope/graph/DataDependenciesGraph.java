package iotscope.graph;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * DataDependenciesGraph
 * If  there  are  any  variables  that contribute to the computation of v0,
 * we add them to our data dependence  graph  (DDG)  and  meanwhile  push  the  involved instructions
 * and  variables  into  a  string  computation  stack
 */
public class DataDependenciesGraph {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataDependenciesGraph.class);

    private final HashSet<IDataDependenciesGraphNode> nodes = new HashSet<>();

    private long time = 0;

    public void addNode(IDataDependenciesGraphNode node) {
        nodes.add(node);
    }


    public void solve(List<ValuePoint> valuePoints) {
        for (ValuePoint valuePoint : valuePoints) {
            this.addNode(valuePoint);
        }

        while (true) {
            long startTime = System.currentTimeMillis();
            initAllIfNeed();
            long endTime = System.currentTimeMillis();
            time += endTime - startTime;
            IDataDependenciesGraphNode node = getNextSolvableNode();

            if (hasSolvedAllTarget(valuePoints)) {
                LOGGER.info("[DONE]: Solved All Value Points!");
                return;
            }

            if (node == null) {
                LOGGER.info("[DONE]: No Solvable Node Left!");
                if (partiallySolvableNodesLeft()) {
                    continue;
                } else {
                    LOGGER.info("[DONE]: No PartiallySolvable Node Left!");
                    return;
                }
            }
            node.solve();

        }
    }

    /**
     * Init nodes -> create Backward Contexts
     */
    private void initAllIfNeed() {
        while (true) {
            IDataDependenciesGraphNode whoNeedInit = null;
            for (IDataDependenciesGraphNode tmp : this.nodes) {
                if (!tmp.inited()) {
                    whoNeedInit = tmp;
                    break;
                }
            }
            if (whoNeedInit == null) {
                return;
            }
            whoNeedInit.initIfHaveNot();
        }
    }

    private IDataDependenciesGraphNode getNextSolvableNode() {
        for (IDataDependenciesGraphNode tmp : this.nodes) {
            if (tmp.getUnsovledDependentsCount() == 0 && !tmp.hasSolved()) {
                return tmp;
            }
        }
        return null;
    }

    /**
     * Can a node be partially solved
     *
     * @return true in case there is such node
     */
    private boolean partiallySolvableNodesLeft() {
        for (IDataDependenciesGraphNode tmp : this.nodes) {
            //added not solved check otherwise some results are added twice
            if (!tmp.hasSolved() && tmp.canBePartiallySolve()) {
                return true;
            }
        }
        return false;
    }

    /**
     * check if all value points have been solved
     *
     * @param valuePoints to check
     * @return true in case all are solved
     */
    private boolean hasSolvedAllTarget(List<ValuePoint> valuePoints) {
        for (ValuePoint vp : valuePoints) {
            if (!vp.hasSolved())
                return false;
        }
        return true;
    }


    public long getBackTime() {
        return time;
    }

}
