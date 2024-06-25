package iotscope.base;

import iotscope.graph.CallGraph;
import iotscope.graph.CallGraphNode;
import iotscope.main.Config;
import iotscope.utility.BlockGenerator;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.FieldRef;
import soot.jimple.Stmt;
import soot.tagkit.AnnotationTag;
import soot.tagkit.Tag;
import soot.tagkit.VisibilityAnnotationTag;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.CompleteBlockGraph;

import java.util.*;

public class StmtPoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(StmtPoint.class);

    private final SootMethod methodLocation;
    private final Block blockLocation;
    private final Unit instructionLocation;

    /**
     * Stmt Point with the location of the stmt (for example the stmt which calls the method signature (method))
     *
     * @param methodLocation      of the stmt
     * @param blockLocation       of the stmt
     * @param instructionLocation of the stmt
     */
    public StmtPoint(SootMethod methodLocation, Block blockLocation, Unit instructionLocation) {
        this.methodLocation = methodLocation;
        this.blockLocation = blockLocation;
        this.instructionLocation = instructionLocation;
    }

    public SootMethod getMethodLocation() {
        return methodLocation;
    }


    public Block getBlockLocation() {
        return blockLocation;
    }


    public Unit getInstructionLocation() {
        return instructionLocation;
    }


    public static List<StmtPoint> findCaller(String signature) {
        return findCaller(signature, false);
    }


    private static Map<String, Set<SootMethod>> annotationSootMethod = new HashMap<>();


    public static void createAnnotationMap() {
        for (SootClass clazz : Scene.v().getClasses()) {
            for (SootMethod method : clazz.getMethods()) {
                for (Tag tag : method.getTags()) {
                    if (tag instanceof VisibilityAnnotationTag) {
                        VisibilityAnnotationTag annotationTag = (VisibilityAnnotationTag) tag;
                        for (AnnotationTag annotation : annotationTag.getAnnotations()) {
                            Set<SootMethod> current = annotationSootMethod.getOrDefault(annotation.getType(), new HashSet<SootMethod>());
                            current.add(method);
                            annotationSootMethod.put(annotation.getType(), current);
                        }
                    }
                }
            }
        }
    }

    private static SootMethod findParentMethod(String signature) {
        SootMethod result = null;

        try {
            String className = signature.substring(signature.indexOf("<")+1, signature.indexOf(":")).trim();
            String methodSubName = signature.substring(signature.indexOf(":")+1).replace(">", "").trim();
            SootClass sootClass = Scene.v().getSootClass(className);
            while (!sootClass.getName().equals("java.lang.Object")) {
                try {
                    result = sootClass.getMethod(methodSubName);
                } catch (RuntimeException e) {
                    LOGGER.debug(String.format("%s not found in %s", methodSubName, sootClass.getName()));
                }
                sootClass = sootClass.getSuperclass();
            }

        } catch (Throwable e) {
            LOGGER.debug(String.format("could not find parent method of %s ", signature));

        }
        return result;
    }

    /**
     * Search for the callers of the passed signature
     *
     * @param signature of the soot method
     * @return found callers
     */
    public static List<StmtPoint> findCaller(String signature, boolean findSubMethods) {
        SootMethod sootMethod = null;
        try {
            sootMethod = Scene.v().getMethod(signature);

        } catch (RuntimeException e) {
            LOGGER.debug(String.format("%s not found", signature));
            sootMethod = findParentMethod(signature);
            findSubMethods = true;
        }

        if (sootMethod == null) {
            return new LinkedList<>();
        }

        HashSet<SootMethod> methods = new HashSet<>();
        methods.add(sootMethod);
        if (Config.PARSEINTERFACECALL && sootMethod.getName().charAt(0) != '<') {
            findAllPointerOfThisMethod(methods, sootMethod.getSubSignature(), sootMethod.getDeclaringClass());
        }
        if (findSubMethods) {
            findAllSubPointerOfThisMethod(methods, sootMethod.getSubSignature(), sootMethod.getDeclaringClass());
        }
        List<StmtPoint> stmtPoints = new ArrayList<>();
        for (SootMethod tmpMethod : methods) {
            CallGraphNode node = CallGraph.getNode(tmpMethod.toString());
            if (node == null) {
                LOGGER.debug("CallGraph node is null");
                continue;
            }
            for (CallGraphNode calledByNode : node.getCallBy()) {
                PatchingChain<Unit> units = calledByNode.getSootMethod().retrieveActiveBody().getUnits();
                for (Unit unit : units) {
                    if (unit instanceof Stmt) {
                        if (((Stmt) unit).containsInvokeExpr()) {
                            try {
                                //search for the stmt where the method (which we are looking for) gets invoked
                                if (((Stmt) unit).getInvokeExpr().getMethod().equals(node.getSootMethod())) {
                                    //In case it is found, it generates the Block graph of the caller method
                                    CompleteBlockGraph completeBlockGraph = BlockGenerator.getInstance().generate(calledByNode.getSootMethod().retrieveActiveBody(), false);
                                    Block block = findLocatedBlock(completeBlockGraph, unit);
                                    stmtPoints.add(new StmtPoint(calledByNode.getSootMethod(), block, unit));
                                }
                            } catch (Exception e) {
                                LOGGER.debug("Could not investigate method call");
                            }
                        }
                    }
                }
            }
        }
        return stmtPoints;
    }

    public static List<StmtPoint> findSetter(SootField sootField) {
        List<StmtPoint> stmtPoints = new ArrayList<>();

        HashSet<SootMethod> sootMethods = CallGraph.getSetter(sootField);
        CompleteBlockGraph completeBlockGraph;
        Block block;
        if (sootMethods != null) {
            for (SootMethod currentMethod : sootMethods) {
                PatchingChain<Unit> units = currentMethod.retrieveActiveBody().getUnits();
                for (Unit unit : units) {
                    if (unit instanceof Stmt) {
                        for (ValueBox valueBox : ((Stmt) unit).getDefBoxes()) {
                            if (valueBox.getValue() instanceof FieldRef && ((FieldRef) valueBox.getValue()).getField() == sootField) {
                                completeBlockGraph = BlockGenerator.getInstance().generate(currentMethod.retrieveActiveBody(), false);
                                block = findLocatedBlock(completeBlockGraph, unit);
                                stmtPoints.add(new StmtPoint(currentMethod, block, unit));
                            }
                        }
                    }
                }
            }
        } else {
            LOGGER.debug("no Setter " + sootField);
        }

        return stmtPoints;
    }


    /**
     * Search for the block containing the unit passed
     *
     * @param completeBlockGraph to search for unit
     * @param unit               to search for
     * @return block containing the unit or null
     */
    public static Block findLocatedBlock(CompleteBlockGraph completeBlockGraph, Unit unit) {
        for (Block block : completeBlockGraph.getBlocks()) {
            for (Unit value : block) {
                if (value == unit) {
                    return block;
                }
            }
        }
        return null;
    }

    /**
     * search for methods implementing signature in case it is an Interface/abstract class?
     *
     * @param methods   resulting methods
     * @param subSig    of the method searched
     * @param sootClass where to look for the method signature
     */
    private static void findAllPointerOfThisMethod(HashSet<SootMethod> methods, String subSig, SootClass sootClass) {
        if (sootClass == null) {
            LOGGER.debug("Soot Class is null in findAllPointerOfThisMethod");
            return;
        }
        try {
            if (sootClass.getMethod(subSig) != null) {
                methods.add(sootClass.getMethod(subSig));
            }
        } catch (Exception e) {
            LOGGER.debug("Caught the exception {}", e.getLocalizedMessage());
        }

        if (sootClass.toString().equals("java.lang.Object")) {
            return;
        }

        if (sootClass.getSuperclass() != sootClass && sootClass.getSuperclass() != null) {
            //no multiple superclasses possible in java
            findAllPointerOfThisMethod(methods, subSig, sootClass.getSuperclass());
        }
        for (SootClass itf : sootClass.getInterfaces()) {
            findAllPointerOfThisMethod(methods, subSig, itf);
        }
    }

    public static void findAllSubPointerOfThisMethod(HashSet<SootMethod> methods, String subSig, SootClass sootClass) {
        HashSet<SootClass> sootClasses = new HashSet<>();
        try {
            sootClasses.addAll(Scene.v().getActiveHierarchy().getSubclassesOf(sootClass));
        } catch (Exception e) {
            LOGGER.debug("Could not get subclasses");
        }
        try {
            sootClasses.addAll(Scene.v().getActiveHierarchy().getSubinterfacesOf(sootClass));
        } catch (Exception e) {
            LOGGER.debug("Could not get subinterfaces");
        }

        sootClasses.forEach(x -> {
            try {
                methods.add(x.getMethod(subSig));
            } catch (Exception e) {
                LOGGER.debug("Method not implemented");
            }
        });
    }

    /**
     * : Find statements that use a global variable ( e.g., $r0 = sootField )
     * @param sootField
     * @return
     */

    public static List<StmtPoint> findUses(SootField sootField) {
		//EDIT
		List<StmtPoint> stmtPoints = new ArrayList<StmtPoint>();

		HashSet<SootMethod> interestingMethods = CallGraph.getUses(sootField);
		CompleteBlockGraph cbg;
		Block block;
		if (interestingMethods != null) {
			for (SootMethod mthd : interestingMethods) {
				PatchingChain<Unit> unitChain = mthd.retrieveActiveBody().getUnits();
				for (Unit unit : unitChain) {
					if (unit instanceof Stmt) {
						for (ValueBox vbox : ((Stmt) unit).getUseBoxes()) {
							if (vbox.getValue() instanceof FieldRef && ((FieldRef) vbox.getValue()).getField() == sootField) {
								cbg = BlockGenerator.getInstance().generate(mthd.retrieveActiveBody(), false);
								block = BlockGenerator.findLocatedBlock(cbg, unit);
								stmtPoints.add(new StmtPoint(mthd, block, unit));
							}
						}
					}
				}
			}
		} else {
			LOGGER.debug("no Uses " + sootField);
		}

		return stmtPoints;
	}


    public JSONObject toJson() {
        JSONObject js = new JSONObject();
        js.put("method", this.getMethodLocation());
        js.put("block", this.getBlockLocation().getIndexInMethod());
        js.put("stmt", this.getInstructionLocation());
        return js;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StmtPoint stmtPoint = (StmtPoint) o;
        return Objects.equals(methodLocation, stmtPoint.methodLocation) && Objects.equals(blockLocation, stmtPoint.blockLocation) && Objects.equals(instructionLocation, stmtPoint.instructionLocation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodLocation, blockLocation, instructionLocation);
    }
}
