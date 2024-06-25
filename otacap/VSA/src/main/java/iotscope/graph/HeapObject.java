package iotscope.graph;

import iotscope.base.StmtPoint;
import iotscope.symbolicsimulation.Constraint;
import iotscope.symbolicsimulation.SymbolicContext;
import iotscope.symbolicsimulation.SymbolicController;
import iotscope.symbolicsimulation.SymbolicSolver;
import iotscope.utility.ConstraintUtil;
import iotscope.utility.ReflectionHelper;
import iotscope.utility.General;

import org.apache.logging.log4j.core.layout.SyslogLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Local;
import soot.PointsToAnalysis;
import soot.PointsToSet;
import soot.Scene;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.DefinitionStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.StaticFieldRef;
import soot.tagkit.*;
import soot.util.Chain;

import java.util.*;
import java.util.Map.Entry;


public class HeapObject implements IDataDependenciesGraphNode {

    private static final Logger LOGGER = LoggerFactory.getLogger(HeapObject.class);

    private final DataDependenciesGraph dataGraph;

    private final SootField sootField;
    private boolean inited = false;
    private boolean solved = false;

    private long symTime = 0;

    public long getTime() {
        return symTime;
    }

    //Value point where the heap object is set
    private ArrayList<ValuePoint> valuePoints;
    private final HashSet<ValuePoint> solvedValuePoints = new HashSet<>();

    private LinkedHashSet<String> errors;

    private final Map<Integer, Set<Object>> result = new HashMap<>();

    private HeapObject(DataDependenciesGraph dataGraph, SootField sootField) {
        this.dataGraph = dataGraph;
        this.sootField = sootField;
        errors = new LinkedHashSet<String>();
    }

    private final static HashMap<String, HeapObject> HEAP_OBJECT_HASH_MAP = new HashMap<>();

    public static HeapObject getInstance(DataDependenciesGraph dataGraph, SootField sootField) {
        if (sootField == null) {
            return null;
        }
        String str = sootField.toString();
        if (!HEAP_OBJECT_HASH_MAP.containsKey(str)) {
            HEAP_OBJECT_HASH_MAP.put(str, new HeapObject(dataGraph, sootField));
        }
        return HEAP_OBJECT_HASH_MAP.get(str);
    }


    @Override
    public Set<IDataDependenciesGraphNode> getDependents() {
        return new HashSet<>(valuePoints);

    }

    @Override
    public int getUnsovledDependentsCount() {
        int count = 0;
        for (IDataDependenciesGraphNode vp : getDependents()) {
            if (!vp.hasSolved()) {
                count++;
            }
        }
        return count;
    }

    @Override
    public boolean hasSolved() {
        return solved;
    }

    @Override
    public void solve() {
        this.solved = true;
        LOGGER.debug("[HEAP SOLVE]" + this.sootField);
        LOGGER.debug("[SOLVING ME]" + this.hashCode());

        for (ValuePoint valuePoint : this.valuePoints) {
            Map<Integer, Set<Object>> vpResult = valuePoint.getResult();
            if (vpResult.containsKey(-1)) {
                Set<Object> toAdd = result.getOrDefault(-1, new HashSet<>());
                vpResult.get(-1).forEach(x -> {
                    try {
                            toAdd.add(x);
                    } catch (Throwable e) {
                        LOGGER.debug("Could not add result object {}", e.getMessage());
                    }
                });
                result.put(-1, toAdd);
            } 
            
            for (Set<Object> resSet : vpResult.values()) {
                if(resSet.isEmpty()) {
                    errors.add(String.format("[HeapObject -> solve] Could not solve field: %s (result set is empty). Method: %s", this.sootField, valuePoint.getMethodLocation()));
                    
                }
                for( Object res : resSet) {
                    if(res == null) {
                        errors.add(String.format("[HeapObject -> solve] Could not solve field: %s (result in set is null). Method: %s", this.sootField, valuePoint.getMethodLocation()));
                    } else if (res.equals("") || res.equals("null")) {
                        errors.add(String.format("[HeapObject -> solve] Could not solve field: %s (result in set is an empty string). Method: %s", this.sootField, valuePoint.getMethodLocation()));
                    }
                } 
            }
            
        }

        //symbolicExec();

        if(!General.startsWithAny(this.sootField.getDeclaringClass().toString())) {
            boolean someValue = false;

            Map<Integer, Set<Object>> tmpMap = this.getResult();
            Collection<Set<Object>> vals = tmpMap.values();
            for(Object val : vals) {
                if(val instanceof HashSet) {
                    HashSet<Object> hsVal = (HashSet<Object>) val;
                    Iterator<Object> it = hsVal.iterator(); 
                    while (it.hasNext()) {

                        Object obj = it.next();
                        if (obj instanceof String)
                            if(!obj.equals("")){
                                someValue = true;
                                break;
                            }
                    } 
                }
            }
            if (!someValue) {
                symbolicExec();
            }
        }

        addDefault();
    }

    private void addDefault() {
        if (!result.containsKey(-1)) {
            Set<Object> toAdd = new HashSet<>();
            toAdd.add(this.sootField.getName());
            result.put(-1, toAdd);
        }
    }

    @Override
    public boolean canBePartiallySolve() {
        boolean canBePartiallySolved = false;
        for (ValuePoint valuePoint : this.valuePoints) {
            if (!this.solvedValuePoints.contains(valuePoint) && valuePoint.hasSolved()) {
                this.solvedValuePoints.add(valuePoint);
                canBePartiallySolved = true;
                Map<Integer, Set<Object>> res = valuePoint.getResult();
                if (res.containsKey(-1)) {
                    Set<Object> toAdd = result.getOrDefault(-1, new HashSet<>());
                    for (Object obj : res.get(-1)) {
                            try {
                                toAdd.add(obj);
                            }catch (ClassCastException e) {
                                //we can't do anything
                            }
                    }
                    result.put(-1, toAdd);
                }
            }

        }
        if (canBePartiallySolved) {
            solved = true;
            addDefault();
        }
        return canBePartiallySolved;
    }

    private void addValueToResult(Object valueToAdd) {
        try {
            Set<Object> toAdd = result.getOrDefault(-1, new HashSet<>());
                toAdd.add(valueToAdd);
                result.put(-1, toAdd);
        } catch (Throwable e) {
            LOGGER.error("could not add reflection object " );
        }
    }

    @Override
    public void initIfHaveNot() {
        this.valuePoints = new ArrayList<>();
        System.out.println("\n\n============ ANALIZING FIELD =============\n"+this.sootField.toString());
        if (this.sootField.getDeclaringClass().isEnum()) {
            System.out.println("is Enum");
            Object toAdd = ReflectionHelper.getEnumObject(sootField, sootField.getDeclaringClass().getName());
            if (toAdd == null) {
                toAdd = sootField.getName();
            }
            addValueToResult(toAdd);
            inited = true;
            return;
        } else {
            Object object = ReflectionHelper.getDefaultValue(sootField, sootField.getDeclaringClass().getName());
            if (object != null) {
                addValueToResult(object);
            } else {
                Optional<Tag> constantTag = this.sootField.getTags().stream().filter(t -> t instanceof ConstantValueTag).findFirst();
                if (constantTag.isPresent()) {
                    Tag tag = constantTag.get();
                    System.out.println("has tag: " + tag);
                    LOGGER.info("Init SootField {} with Value {}", this.sootField, tag);
                    if (tag instanceof StringConstantValueTag) {
                        addValueToResult(((StringConstantValueTag) tag).getStringValue());
                    } else if (tag instanceof IntegerConstantValueTag) {
                        addValueToResult(((IntegerConstantValueTag) tag).getIntValue());
                    } else if (tag instanceof FloatConstantValueTag) {
                        addValueToResult(((FloatConstantValueTag) tag).getFloatValue());
                    } else if (tag instanceof LongConstantValueTag) {
                        addValueToResult(((LongConstantValueTag) tag).getLongValue());
                    } else if (tag instanceof DoubleConstantValueTag) {
                        addValueToResult(((DoubleConstantValueTag) tag).getDoubleValue());
                    }
                } else {
                    
                }
            }
        }


        List<StmtPoint> stmtPoints = StmtPoint.findSetter(this.sootField);
        if(stmtPoints.size() == 0) {
            errors.add(String.format("[StmtPoint -> findSetter] Could not find setters for field: %s", this.sootField));
        }
        for (StmtPoint stmtPoint : stmtPoints) {
            ValuePoint tmp = new ValuePoint(dataGraph, stmtPoint.getMethodLocation(), stmtPoint.getBlockLocation(), stmtPoint.getInstructionLocation(), Collections.singletonList(-1));
            valuePoints.add(tmp);
            tmp.setCreatingHeapObject(this);
        }


        LOGGER.debug("[HEAP INIT]" + sootField + " " + StmtPoint.findSetter(sootField).size());
        inited = true;

    }

    @Override
    public boolean inited() {
        return inited;
    }

    @Override
    public Set<IDataDependenciesGraphNode> getDirectAndIndirectDependents
            (Set<IDataDependenciesGraphNode> nodesToGetDependencies) {
        for (IDataDependenciesGraphNode i : this.getDependents()) {
            if (!nodesToGetDependencies.contains(i)) {
                nodesToGetDependencies.add(i);
                i.getDirectAndIndirectDependents(nodesToGetDependencies);
            }
        }
        return nodesToGetDependencies;
    }

    @Override
    public Map<Integer, Set<Object>> getResult() {
        return result;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((sootField == null) ? 0 : sootField.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HeapObject other = (HeapObject) obj;
        if (sootField == null) {
            return other.sootField == null;
        } else {
            return sootField.equals(other.sootField);
        }
    }

    /**
     * : 
     * @param method
     * @param pta
     * @param sf
     * @return
     */
    private ArrayList<Local> findAlias(SootMethod method, PointsToAnalysis pta, SootField sf) {
		ArrayList<Local> aliased = new ArrayList<>();
		Chain<Unit> units = method.getActiveBody().getUnits();
		PointsToSet orig = null;
		HashMap<Local, PointsToSet> nonEmpty = new HashMap<>();
		for (Unit unit : units) {
			if (unit instanceof DefinitionStmt) {
				DefinitionStmt defStmt = (DefinitionStmt) unit;
                Value leftOp = defStmt.getLeftOp();
                Value rightOp = defStmt.getRightOp();
                if(leftOp instanceof Local) {
	                PointsToSet leftPointsToSet = pta.reachingObjects((Local) leftOp);
	                
	                if(rightOp instanceof InstanceFieldRef) {
	                	if( sf.equals(((InstanceFieldRef)rightOp).getField()) ){
	                		orig = leftPointsToSet;
	                		PointsToSet rightPointsToSet = pta.reachingObjects(sf);
	                		if(!rightPointsToSet.isEmpty()) {
	                			nonEmpty.put((Local)leftOp, rightPointsToSet);
	                		}
	                	}
	                } else if(rightOp instanceof StaticFieldRef) {
	                	if( sf.equals(((StaticFieldRef)rightOp).getField()) ){
	                		orig = leftPointsToSet;
	                		PointsToSet rightPointsToSet = pta.reachingObjects(sf);
	                		if(!rightPointsToSet.isEmpty()) {
	                			nonEmpty.put((Local)leftOp, rightPointsToSet);
	                		}
	                	}
	                }
	                
	                if(!leftPointsToSet.isEmpty() ) {
	                	for (Type t : leftPointsToSet.possibleTypes()) {
	                		if(t.toString().contains("java.lang.String")) {
	                			nonEmpty.put((Local)leftOp,leftPointsToSet);
	                        	break;
	                		}
	                	}
	                }
                }
			}
		}
		
		for(Entry<Local, PointsToSet> entry : nonEmpty.entrySet()) {
			if(orig!= null && orig.hasNonEmptyIntersection(entry.getValue())) {
				aliased.add(entry.getKey());
			}
		}
		return aliased;
	}


    @Override
    public String toString() {
        if (!inited)
            return super.toString();
        StringBuilder sb = new StringBuilder();
        sb.append("===========================");
        sb.append(this.hashCode());
        sb.append("===========================\n");
        sb.append("Field: ").append(sootField).append("\n");
        sb.append("Solved: ").append(hasSolved()).append("\n");
        sb.append("Depend: ");
        for (IDataDependenciesGraphNode var : this.getDependents()) {
            sb.append(var.hashCode());
            sb.append(", ");
        }
        sb.append("\n");
        sb.append("ValueSet: \n");
        Map<Integer, Set<Object>> resultMap = result;
        sb.append("  ");
        for (int i : resultMap.keySet()) {
            sb.append(" |").append(i).append(":");
            for (Object str : resultMap.get(i)) {
                sb.append(str == null ? "" : str.toString()).append(",");
            }
        }
        sb.append("\n");


        return sb.toString();
    }

    public LinkedHashSet<String> getErrors() {
        return errors;
    }

    public void appendErrors(String message) {
        errors.add(message);
    }

    public SootField getSootField() {
        return this.sootField;
    }

public void symbolicExec() {
        System.out.println("Symbolic analysis");
        long startTime = System.currentTimeMillis();
        List<StmtPoint> stmtUses = StmtPoint.findUses(sootField);
        for (StmtPoint stmtPoint : stmtUses) {
            SootMethod methodContainer = stmtPoint.getMethodLocation();
            PointsToAnalysis poinsToAnalysis = Scene.v().getPointsToAnalysis();
            ArrayList<Local> aliases = findAlias(methodContainer, poinsToAnalysis, sootField);
            if(aliases!=null && aliases.size()>0) {
                boolean foundValues= false;
                for(Local item : aliases) {

                    // Create a new type of value point that better meet the requirements of SE
                    SValuePoint symbolicPoint = new SValuePoint(dataGraph, stmtPoint.getMethodLocation(), stmtPoint.getBlockLocation(), stmtPoint.getInstructionLocation(), item);
                    // Add point to forward symbolic engine
                    SymbolicController symbol = SymbolicController.getInstance();
                    List<SymbolicContext> symRes = symbol.doForward(symbolicPoint, dataGraph);

                    List<List<Constraint>> combined = new ArrayList<>();
                    List<Constraint> toSolver = new ArrayList<>();
                    
                    for(SymbolicContext context : symRes) {

                        List<Constraint> constrs = context.getConstraints();

                        if(constrs != null){
                            for (Constraint c : constrs) {
                                if(!hasEquivalent(toSolver, c)) {
                                    toSolver.add(c);
                                }
                            }
                        }
                    }

                    if(toSolver.size()==0){
                        continue;
                    }
                    
                    combined =  ConstraintUtil.makeCombinations(toSolver);
                    toSolver = null;

                    if (combined.size() > 64) {
                        combined = null;
                        continue;
                    }

                    for (List<Constraint> temp : combined) {
                        SymbolicSolver ss;

                        if(!hasConcreteValue(temp)){
                            continue;
                        }
                        
                        try {
                            ss = new SymbolicSolver();
                        } catch (RuntimeException e) {
                            continue;
                        }

                        for(Constraint constrToAdd : temp) {
                            ss.addConstraint(constrToAdd.getOperation(), constrToAdd.getLeft(), constrToAdd.getRigh(), constrToAdd.getLeftBase(), constrToAdd.getRightBase(), constrToAdd.isNegated());
                        }
                        
                        String simResult = ss.solve(ConstraintUtil.getVarName(item));
                        ss = null;
                        addValueToResult(simResult);
                        
                        if(!foundValues && simResult != null){
                            if(simResult.trim()!="null" && simResult.trim()!="")
                                foundValues = true;
                        }
                    }
                    if(foundValues) {
                        break;
                    }
                    combined = null;
                }
            }
        }

        long endTime = System.currentTimeMillis();
        symTime += endTime - startTime;
    }


    private boolean hasEquivalent(List<Constraint> list, Constraint constraint) {
        boolean result = false;
        for(Constraint c : list){
            if(c.getLeft().equals(constraint.getLeft())){
                if(c.getOperation().equals(constraint.getOperation())){
                    if(c.getRigh().equals(constraint.getRigh())){
                        result = true;

                        if(constraint.getLeftBase()!=null){
                            if(!constraint.getLeftBase().equals(c.getLeftBase())){
                                result = false;
                            }
                        }
                        if(constraint.getRightBase()!=null){
                            if(!constraint.getRightBase().equals(c.getRightBase())){
                                result = false;
                            }
                        }

                    }
                }
            }
        }
        return result;
    }

    private boolean hasConcreteValue(List<Constraint> list) {
        for(Constraint c : list){
            if(c.getRigh().contains("STR:"))
                return true;
        }
        return false;
    }
}
