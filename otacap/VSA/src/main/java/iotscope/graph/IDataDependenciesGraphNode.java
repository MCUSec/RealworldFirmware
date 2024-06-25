package iotscope.graph;

import java.util.Map;
import java.util.Set;

/**
 * DataDependenciesGraphNode -> Value Point or Heap Objet
 */
public interface IDataDependenciesGraphNode {

    /**
     * @return dependent nodes
     */
    Set<IDataDependenciesGraphNode> getDependents();

    /**
     * @return the number of not solve dependents node
     */
    int getUnsovledDependentsCount();

    /**
     * @return true if the node is solved
     */
    boolean hasSolved();

    /**
     * solve Value Points with simulation engines
     */
    void solve();

    /**
     * @return if the Node can be partially solved (and tries to solve the value point)
     */
    boolean canBePartiallySolve();

    /**
     * Inits the Node if it has not already been initialized
     */
    void initIfHaveNot();

    /**
     * Return true if the node is already inited
     *
     * @return inited
     */
    boolean inited();

    /**
     * @return the results
     */
    Map<Integer, Set<Object>> getResult();

    Set<IDataDependenciesGraphNode> getDirectAndIndirectDependents(Set<IDataDependenciesGraphNode> ret);
}
