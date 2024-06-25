package iotscope.forwardexec;

import iotscope.backwardslicing.StmtPath;
import iotscope.base.ParameterTransferStmt;
import iotscope.base.StmtPoint;
import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import iotscope.forwardexec.objectSimulation.cloud.AwsCredentialSimulation;
import iotscope.forwardexec.objectSimulation.coap.CaliforniumCoapClientSimulation;
import iotscope.forwardexec.objectSimulation.coap.CoapMediaTypeSimulation;
import iotscope.forwardexec.objectSimulation.coap.CoapRequestCodeSimulation;
import iotscope.forwardexec.objectSimulation.general.*;
import iotscope.forwardexec.objectSimulation.json.GoogleGsonSimulation;
import iotscope.forwardexec.objectSimulation.json.JacksonJsonSimulation;
import iotscope.forwardexec.objectSimulation.json.MoshiSimulation;
import iotscope.forwardexec.objectSimulation.json.OrgJSONObjectSimulation;
import iotscope.forwardexec.objectSimulation.mqtt.*;
import iotscope.forwardexec.objectSimulation.network.*;
import iotscope.forwardexec.objectSimulation.xmpp.JiveSoftwareSmackConstants;
import iotscope.forwardexec.objectSimulation.xmpp.JxmppJidSimulation;
import iotscope.graph.DataDependenciesGraph;
import iotscope.graph.HeapObject;
import iotscope.utility.TimeWatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.*;
import soot.jimple.internal.AbstractFloatBinopExpr;

import java.util.*;
import java.util.concurrent.*;

/**
 * computes the string functionalities forward
 */
public class SimulateEngine extends AbstractStmtSwitch {
    private static final Logger LOGGER = LoggerFactory.getLogger(SimulateEngine.class);

    private final DataDependenciesGraph dataGraph;
    private final StmtPath stmtPath;
    private final HashMap<Value, HashSet<?>> currentValues = new HashMap<>();
    private final List<SimulationObjects> simulationList;
    private static final Set<SootMethod> cannotSimulate = new HashSet<>();

    private LinkedHashSet<String> errors;

    public SimulateEngine(DataDependenciesGraph dataGraph, StmtPath stmtPath) {
        this.dataGraph = dataGraph;
        this.stmtPath = stmtPath;
        simulationList = new LinkedList<>();
        simulationList.add(new JavaNetUrlSimulation());
        simulationList.add(new StringSimulation());
        simulationList.add(new OkHttpSimulation());
        simulationList.add(new IntegerSimulation());
        simulationList.add(new JavaNetUriSimulation());
        simulationList.add(new JavaNetSocketAddressSimulation());
        simulationList.add(new JavaNetInetAddressSimulation());
        simulationList.add(new JavaxSocketFactorySimulation());

        simulationList.add(new MapSimulation());
        simulationList.add(new ListSimulation());
        simulationList.add(new SetSimulation());


        simulationList.add(new GoogleGsonSimulation());
        simulationList.add(new OrgJSONObjectSimulation());
        simulationList.add(new MoshiSimulation());
        simulationList.add(new JacksonJsonSimulation());

        simulationList.add(new AndroidSpecificSimulation());
        simulationList.add(new DoubleSimulation());
        simulationList.add(new FloatSimulation());
        simulationList.add(new LongSimulation());
        simulationList.add(new AndroidNetUriSimulation());
        simulationList.add(new ByteSimulation());
        simulationList.add(new HiveMqttClient());
        simulationList.add(new HiveMqttTopic());
        simulationList.add(new HiveMqttDatabaseBasic());
        simulationList.add(new PahoMqtt3Message());
        simulationList.add(new FuesourceMqttClientTopicSimulation());

        simulationList.add(new CaliforniumCoapClientSimulation());
        simulationList.add(new CoapMediaTypeSimulation());
        simulationList.add(new CoapRequestCodeSimulation());

        simulationList.add(new JiveSoftwareSmackConstants());
        simulationList.add(new JxmppJidSimulation());
        simulationList.add(new AwsCredentialSimulation());


        simulationList.add(new ApacheSimulation());
        simulationList.add(new LoopjSimulation());
        simulationList.add(new FileSimulation());

        simulationList.add(new BooleanSimulation());

        errors = new LinkedHashSet<String>();
    }


    public StmtPath getStmtPath() {
        return stmtPath;
    }

    public HashMap<Value, HashSet<?>> getCurrentValues() {
        return currentValues;
    }


    public void simulate() {
        Unit lastUnit = getStmtPath().getStmtPathTail();
        for (StmtPoint stmtPoint : getStmtPath().getStmtPath()) {
            Stmt stmt = (Stmt) stmtPoint.getInstructionLocation();

            if (stmt == lastUnit) {
                return;
            }
            if (TimeWatcher.getTimeWatcher().getTimeoutForwardIsUP()) {
                TimeWatcher.getTimeWatcher().markTimeoutForwardUsed();
                return;
            }
            LOGGER.debug("[SIMULATE]" + this.hashCode() + ": " + stmt + " " + stmt.getClass());
            if (stmt instanceof ParameterTransferStmt) {
                caseAssignStmt((AssignStmt) stmt);
            } else {
                stmt.apply(this);
            }

        }
    }


    @Override
    public void caseInvokeStmt(InvokeStmt stmt) {
        String signature = stmt.getInvokeExpr().getMethod().toString();
        InvokeExpr invokeExpr = stmt.getInvokeExpr();
        Value base = null;
        if (invokeExpr instanceof InstanceInvokeExpr) {
            base = ((InstanceInvokeExpr) invokeExpr).getBase();
        }

        for (SimulationObjects simulation : simulationList) {
            HashSet<?> result = simulation.handleInvokeStmt(stmt, signature, invokeExpr, currentValues);
            if (result != null && result.size() > 0) {
                // assign Value
                copyValueTo(result, base);
                return;
            }
        }

        HashSet<?> result = executeInvokeExpr(invokeExpr, true);
        if (result != null && result.size() > 0) {
            copyValueTo(result, base);
            return;
        }

        super.caseInvokeStmt(stmt);
    }

    private static ExecutorService executor = Executors.newSingleThreadExecutor();
    public static Thread executorThread = null;


    private HashSet<?> executeInvokeExpr(InvokeExpr invokeExpr, boolean returnBase) {

        if (cannotSimulate.contains(invokeExpr.getMethod())) {
            return new HashSet<>();
        }
        try {

            ReflectionHandling reflectionHandling = new ReflectionHandling(currentValues, invokeExpr, returnBase);

            List<Future<HashSet<?>>> execution = executor.invokeAll(List.of(reflectionHandling), 2, TimeUnit.SECONDS);
            HashSet<?> result = new HashSet<>();
            Future<HashSet<?>> exec = execution.get(0);
            try {
                if (exec.isCancelled()) {
                    LOGGER.debug("Reflection execution did not finish in time for {}", invokeExpr);
                    cannotSimulate.add(invokeExpr.getMethod());
                    try {
                        executor.shutdownNow();
                        Thread.sleep(2);
                        executorThread.stop();
                        Thread.sleep(2);
                    } catch (Throwable e) {

                    }
                    executor = Executors.newSingleThreadExecutor();
                }
                result = exec.get(2, TimeUnit.SECONDS);
            } catch (ExecutionException | TimeoutException e) {

                LOGGER.debug("Reflection result collection did not finish in time for {}", invokeExpr);
                
                cannotSimulate.add(invokeExpr.getMethod());
                try {
                    executor.shutdownNow();
                    Thread.sleep(2);
                    executorThread.stop();
                    Thread.sleep(2);
                } catch (Throwable e2) {
                }
                executor = Executors.newSingleThreadExecutor();
            }

            if (result == null || result.size() == 0) {
                result = reflectionHandling.getResult();
            }
            return result;
        } catch (Throwable e) {
            LOGGER.debug("Invoke expr could not be executed due to {}", e.getLocalizedMessage());
            return new HashSet<>();
        }
    }


    private HashSet<?> handleDefaultInvokeStmt(InvokeExpr invokeExpr) {
        if (invokeExpr instanceof InstanceInvokeExpr) {
            HashSet<?> baseValues = SimulationUtil.getCurrentValues(((InstanceInvokeExpr) invokeExpr).getBase(), currentValues);
            if (baseValues != null && baseValues.size() > 0) {
                return baseValues;
            }
        }

        for (Value arg : invokeExpr.getArgs()) {
            HashSet<?> current = SimulationUtil.getCurrentValues(arg, currentValues);
            if (current != null && current.size() > 0) {
                return current;
            }
        }
        return new HashSet<>();
    }

    @Override
    public void caseAssignStmt(AssignStmt stmt) {
        Value leftOperation = stmt.getLeftOp();
        Value rightOperation = stmt.getRightOp();
        HashSet<?> result = null;
        if (leftOperation instanceof Local || leftOperation instanceof ParameterRef || leftOperation instanceof ArrayRef) {

            if (rightOperation instanceof InvokeExpr) {
                InvokeExpr virtualInvokeExpr = (InvokeExpr) rightOperation;
                String methodSignature = virtualInvokeExpr.getMethod().toString();
                for (SimulationObjects simulation : simulationList) {
                    try {

                        result = simulation.handleAssignInvokeExpression(stmt, methodSignature, virtualInvokeExpr, currentValues);
                        if (result != null && result.size() > 0) {
                            break;
                        }
                    } catch (Throwable e) {
                        LOGGER.error("Assign invoke expression Simulation through an error");
                    }
                }
                //if we don't handle the expression, try to execute it through reflection
                if (result == null || result.size() == 0) {
                    result = executeInvokeExpr(virtualInvokeExpr, false);
                }
                if (result == null || result.size() == 0) {
                    result = handleDefaultInvokeStmt(virtualInvokeExpr);
                }
                LOGGER.debug(String.format("[%s] [SIMULATE][right unknown(VirtualInvokeExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
                errors.add(String.format("[%s] [SIMULATE][right unknown(VirtualInvokeExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
            } else if (rightOperation instanceof NewExpr) {
                for (SimulationObjects simulation : simulationList) {
                    result = simulation.handleAssignNewExpression(stmt, rightOperation, currentValues);
                    if (result != null && result.size() > 0) {
                        break;
                    }
                }

                LOGGER.debug(String.format("[%s] [SIMULATE][right unknown(NewExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
                errors.add(String.format("[%s] [SIMULATE][right unknown(NewExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
            } else if (rightOperation instanceof FieldRef) {
                HeapObject ho = HeapObject.getInstance(dataGraph, ((FieldRef) rightOperation).getField());
                if (ho != null) {
                    if (ho.inited() && ho.hasSolved()) {
                        HashSet<Object> nv = new HashSet<>();
                        Map<Integer, Set<Object>> var = ho.getResult();
                        for( Set<Object> resultSet : var.values()) {
                            for(Object res : resultSet) {
                                String sootField = ho.getSootField().toString();
                                if(res == null) {
                                    ho.appendErrors(String.format("[SimulateEngine -> caseAssignStmt] Could not find setters for field: %s.", sootField));
                                } else {
                                    if(res.getClass().toString().contains("JSONObject")) {
                                        continue;
                                    }
                                    String resultObject = "";
                                    try {
                                        resultObject = Objects.toString(res, "");
                                    } catch(Throwable e) {
                                        ho.appendErrors(String.format("[SimulateEngine -> caseAssignStmt] Could not convert results to string."));
                                    } 
                                    
                                    if (resultObject.equals("")) {
                                        ho.appendErrors(String.format("[SimulateEngine -> caseAssignStmt] Could not find setters for field: %s.", sootField));
                                    } else if(res.toString().toString().equals("null")) {
                                        ho.appendErrors(String.format("[SimulateEngine -> caseAssignStmt] Could not find setters for field: %s.", sootField));
                                    }
                                }
                            }
                        }
                        try {
                            nv.addAll(var.get(-1));
                        } catch (Throwable e) {
                            LOGGER.error("Reflection lead to class cast exception {}", e.getLocalizedMessage());
                            if (var != null) {
                                if (var.get(-1) != null) {
                                    for (Object o : var.get(-1)) {
                                        if (o != null) {
                                            nv.add(o.toString());
                                        }
                                    }
                                }
                            }
                        }
                        copyValueTo(nv, leftOperation);
                    } else {
                        LOGGER.debug(String.format("[%s] [SIMULATE][HeapObject not created or Solved]: %s (%s)", this.hashCode(), stmt, ho.inited()));
                        errors.add(String.format("[%s] [SIMULATE][right unknown(VirtualInvokeExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
                    }
                } else {
                    LOGGER.debug(String.format("[%s] [SIMULATE][HeapObject not found]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
                    errors.add(String.format("[%s] [SIMULATE][HeapObject not found]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
                }

            } else if (rightOperation instanceof NewArrayExpr) {
                for (SimulationObjects simulation : simulationList) {
                    result = simulation.handleAssignNewArrayExpr(stmt, rightOperation, currentValues);

                    if (result != null && result.size() > 0) {
                        break;
                    }
                }
                LOGGER.debug(String.format("[%s] [SIMULATE][right unknown(NewArrayExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
            } else if (rightOperation instanceof AbstractFloatBinopExpr) {
                for (SimulationObjects simulation : simulationList) {
                    result = simulation.handleAssignArithmeticExpr(stmt, rightOperation, currentValues);
                    if (result != null && result.size() > 0) {
                        break;
                    }
                }
                LOGGER.debug(String.format("[%s] [SIMULATE][right unknown(ArithmeticExpr)]: %s (%s)", this.hashCode(), stmt, rightOperation.getClass()));
            } else if (rightOperation instanceof Local || rightOperation instanceof CastExpr || rightOperation instanceof ArrayRef || rightOperation instanceof Constant) {
                // convert chars from their integer representation back to chars
                if(rightOperation instanceof IntConstant) {
                    if(leftOperation.getType().toString().equals("char")) {
                        int intValue = Integer.parseInt(rightOperation.toString());
                        String toConstant = ((char) intValue) + "";
                        rightOperation = StringConstant.v(toConstant);
                    }
                }
                result = SimulationUtil.getCurrentValues(rightOperation, currentValues);
            }
        } else {
            LOGGER.warn(String.format("[%s] [SIMULATE][left unknown]: %s (%s)", this.hashCode(), stmt, leftOperation.getClass()));
            errors.add(String.format("[%s] [SIMULATE][left unknown]: %s (%s)", this.hashCode(), stmt, leftOperation.getClass()));
        }

        if (result != null && result.size() > 0) {
            copyValueTo(result, leftOperation);
        }

    }

    @Override
    public void caseIdentityStmt(IdentityStmt stmt) {
        //Own this ref handling. If it does not exist already create a new Hashmap
        if (stmt.getRightOp() instanceof ThisRef && SimulationUtil.getCurrentValues(stmt.getRightOp(), currentValues) == null) {
            if (SimulationUtil.getCurrentValues(stmt.getLeftOp(), currentValues) == null) {
                HashSet<Map<String, Object>> thisMap = new HashSet<>();
                thisMap.add(new HashMap<>());
                copyValueTo(thisMap, stmt.getLeftOp());
            }
        } else {
            copyValueTo(SimulationUtil.getCurrentValues(stmt.getRightOp(), currentValues), stmt.getLeftOp());
        }
    }

    @Override
    public void defaultCase(Object obj) {
        LOGGER.warn(String.format("[%s] [SIMULATE][Can't Handle]: %s (%s)", this.hashCode(), obj, obj.getClass()));
        errors.add(String.format("[%s] [SIMULATE][Can't Handle]: %s (%s)", this.hashCode(), obj, obj.getClass()));
    }

    public void copyValueTo(HashSet<?> values, Value to) {
        Value key = SimulationUtil.getKeyValue(to);
        if (to instanceof ArrayRef) {
            if (values != null) {
                HashSet<List<?>> result = new HashSet<>();

                int minIndex = SimulationUtil.getMinIndexOfArray(((ArrayRef) to), currentValues);
                HashSet<List<?>> baseArray;
                try {
                    baseArray = (HashSet<List<?>>) currentValues.getOrDefault(((ArrayRef) to).getBase(), new HashSet<>());
                } catch (ClassCastException e) {
                    baseArray = new HashSet<>();
                    baseArray.add(new ArrayList<>());
                }

                List<Object> baseArrayList = Arrays.asList(baseArray.toArray());

                int i = 0;
                for (Object value : values) {
                    List<Object> currentArray;
                    if (baseArrayList.size() <= i && baseArrayList.size() > 0) {
                        try {
                            currentArray = new ArrayList((List) baseArrayList.get(0));
                        } catch (ClassCastException | IndexOutOfBoundsException | NullPointerException e) {
                            currentArray = new ArrayList<>();
                            LOGGER.error(String.format("Is not an Array %s at index 0", baseArrayList));
                        }
                    } else if (baseArrayList.size() == 0) {
                        currentArray = new LinkedList<>();
                    } else {
                        try {
                            currentArray = new ArrayList((List) baseArrayList.get(i));
                        } catch (ClassCastException | IndexOutOfBoundsException | NullPointerException e) {
                            currentArray = new ArrayList<>();
                            LOGGER.error(String.format("Is not an Array %s at index %d", baseArrayList, i));
                        }
                    }
                    if (minIndex < 0) {
                        minIndex = currentArray.size();
                    }
                    if (minIndex > 1000) {
                        minIndex = 1000;
                    }
                    while (currentArray.size() <= minIndex) {
                        currentArray.add(new Object());
                    }
                    currentArray.remove(minIndex);
                    currentArray.add(minIndex, value);
                    result.add(currentArray);
                    i++;
                }

                if (result.size() != 0) {
                    currentValues.put(key, (HashSet<?>) result.clone());
                }
            }
        } else {
            if (values != null) {
                try {
                    currentValues.put(key, (HashSet<?>) values.clone());
                } catch (Throwable e) {
                    currentValues.put(key,  values);
                }
            }
        }
    }

    public LinkedHashSet<String> getErrors() {
        return this.errors;
    }

}
