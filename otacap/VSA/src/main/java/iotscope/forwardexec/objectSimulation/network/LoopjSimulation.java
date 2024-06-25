package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import iotscope.utility.LoopjHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.io.File;
import java.util.*;

public class LoopjSimulation implements SimulationObjects {
    //Request Param
    private static final Logger LOGGER = LoggerFactory.getLogger(LoopjSimulation.class);

    public LoopjSimulation() {
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<cz.msebera.android.httpclient.entity") ||
                !signature.startsWith("cz.msebera.android.httpclient.message") ||
                !signature.startsWith("<com.loopj.android.http.RequestParams")) {
            return null;
        }
        HashSet<String> result = new HashSet<>();
        if (signature.contains("<cz.msebera.android.httpclient.entity.FileEntity: void <init>(")) {
            HashSet<File> arg0 = SimulationUtil.getFile(expr.getArg(0), currentValues);
            arg0.forEach(x -> {
                result.add(x.toString());
            });
        } else if (signature.contains("<cz.msebera.android.httpclient.entity.StringEntity: void <init>(")) {
            HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            result.addAll(arg0);
        } else if (signature.contains("<cz.msebera.android.httpclient.entity.ByteArrayEntity: void <init>(")) {
            HashSet<byte[]> arg0 = SimulationUtil.getByteArrayContent(expr.getArg(0), currentValues);
            arg0.forEach(x -> {
                result.add(Arrays.toString(x));
            });
        } else if (signature.equals("<cz.msebera.android.httpclient.message.BasicHeader: void <init>(java.lang.String,java.lang.String)>")) {
            Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
            Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
            HashSet<LoopjHeader> headerResult = new HashSet<>();
            while (arg0.hasNext() && arg1.hasNext()) {
                headerResult.add(new LoopjHeader(arg0.next(), arg1.next()));
            }
            return headerResult;

        } else if (signature.startsWith("<com.loopj.android.http.RequestParams:")) {
            HashSet<Map<String, Object>> resultMap = new HashSet<>();
            if (signature.equals("<com.loopj.android.http.RequestParams: void <init>(java.util.Map)>")) {
                HashSet<Map> arg0 = SimulationUtil.getMap(expr.getArg(0), currentValues);
                for (Map current : arg0) {
                    Map<String, Object> tmp = new HashMap<>();
                    for (Object currentKey : current.keySet()) {
                        tmp.put(currentKey.toString(), current.get(currentKey));
                    }
                    resultMap.add(tmp);
                }
            } else if (signature.equals("<com.loopj.android.http.RequestParams: void <init>(java.lang.String,java.lang.String)>")) {
                Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
                while (arg0.hasNext() && arg1.hasNext()) {
                    Map<String, Object> tmp = new HashMap<>();
                    tmp.put(arg0.next(), arg1.next());
                    resultMap.add(tmp);
                }
            } else if (signature.equals("<com.loopj.android.http.RequestParams: void <init>()>")) {
                Map<String, Object> tmp = new HashMap<>();
                resultMap.add(tmp);
            } else if (signature.equals("<com.loopj.android.http.RequestParams: void add(java.lang.String,java.lang.String)>")) {
                HashSet<Map> base = SimulationUtil.getLoopjRequestParamMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
                for (Map tmp : base) {
                    Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                    Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
                    while (arg0.hasNext() && arg1.hasNext()) {
                        tmp.put(arg0.next(), arg1.next());
                        resultMap.add(tmp);
                    }
                }
            } else if (signature.contains("<com.loopj.android.http.RequestParams: void put(")) {
                HashSet<Map> base = SimulationUtil.getLoopjRequestParamMap(((InstanceInvokeExpr) expr).getBase(), currentValues);
                if (signature.contains("<com.loopj.android.http.RequestParams: void put(java.lang.String,java.io.File[]")) {
                    for (Map tmp : base) {
                        Iterator<File[]> arg1 = SimulationUtil.getFileArray(expr.getArg(1), currentValues).iterator();
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.contains("<com.loopj.android.http.RequestParams: void put(java.lang.String,java.io.File")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<File> arg1 = SimulationUtil.getFile(expr.getArg(1), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.equals("<com.loopj.android.http.RequestParams: void put(java.lang.String,int)>")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<Integer> arg1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.equals("<com.loopj.android.http.RequestParams: void put(java.lang.String,long)>")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<Long> arg1 = SimulationUtil.getLongContent(expr.getArg(1), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.equals("<com.loopj.android.http.RequestParams: void put(java.lang.String,java.lang.Object)>")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<Object> arg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.equals("<com.loopj.android.http.RequestParams: void put(java.lang.String,java.lang.String)>")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                } else if (signature.equals("<com.loopj.android.http.RequestParams: void put(java.lang.String,java.lang.String,java.io.File)>")) {
                    for (Map tmp : base) {
                        Iterator<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues).iterator();
                        Iterator<File> arg1 = SimulationUtil.getFile(expr.getArg(2), currentValues).iterator();
                        while (arg0.hasNext() && arg1.hasNext()) {
                            tmp.put(arg0.next(), arg1.next());
                            resultMap.add(tmp);
                        }
                    }
                }

            }
            return resultMap;

        }
        return result;
    }


    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (!newArrayExpr.getBaseType().toString().startsWith("cz.msebera.android.httpclient.message")) {
            return null;
        }
        return SimulationUtil.initArray(new LoopjHeader("", ""), newArrayExpr, currentValues);
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }
}
