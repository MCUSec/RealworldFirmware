package iotscope.forwardexec.objectSimulation.json;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.*;

public class OrgJSONObjectSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(OrgJSONObjectSimulation.class);


    public OrgJSONObjectSimulation() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<org.json")) {
            return null;
        }
        HashSet<JSONArray> result = new HashSet<>();
        if (signature.contains("<org.json.JSONArray: void <init>(java.util.Collection)>")) {
            HashSet<Collection> currentArguments = SimulationUtil.getCollection(expr.getArg(0), currentValues);
            HashSet<JSONArray> finalResult = result;
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONArray(x));
                    } else {
                        finalResult.add(new JSONArray());
                    }
                } catch (JSONException e) {
                    finalResult.add(new JSONArray());
                }
            });
            return finalResult;
        } else if (signature.contains("<org.json.JSONArray: void <init>(org.json.JSONArray)>")) {
            HashSet<JSONArray> currentArguments = SimulationUtil.getJSONArrays(expr.getArg(0), currentValues);
            HashSet<JSONArray> finalResult = result;
            currentArguments.forEach(x -> {
                try {

                    if (x != null) {
                        finalResult.add(new JSONArray(x));
                    } else {
                        finalResult.add(new JSONArray());
                    }
                } catch (JSONException e) {
                    finalResult.add(new JSONArray());
                }
            });
            return finalResult;
        } else if (signature.contains("<org.json.JSONArray: void <init>(java.lang.Object)>")) {
            HashSet<Object> currentArguments = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            if (currentArguments.size() == 0) {
                currentArguments.add(new JSONObject().put("FromNotReconstructedObject", true));
            }
            HashSet<JSONArray> finalResult = result;
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONArray(x));
                    } else {
                        finalResult.add(new JSONArray());
                    }
                } catch (JSONException e) {
                    finalResult.add(new JSONArray());
                }
            });
            return finalResult;
        } else if (signature.contains("<org.json.JSONArray: void <init>(java.lang.String)>")) {
            HashSet<String> currentArguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            HashSet<JSONArray> finalResult = result;
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONArray(x));
                    } else {
                        finalResult.add(new JSONArray());
                    }
                } catch (JSONException e) {
                    finalResult.add(new JSONArray());
                }
            });
            return finalResult;
        } else if (signature.startsWith("<org.json.JSONArray: void <init>(")) {
            result.add(new JSONArray());
            return result;
        } else if (signature.startsWith("<org.json.JSONObject: void <init>(org.json.JSONObject,")) {
            HashSet<JSONObject> currentArguments = SimulationUtil.getJSONObjects(expr.getArg(0), currentValues);
            HashSet<JSONObject> finalResult = new HashSet<>();
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONObject(x));
                    } else {
                        finalResult.add(new JSONObject());
                    }
                }catch (JSONException e) {
                    finalResult.add(new JSONObject());
                }
            });
            return finalResult;
        } else if (signature.equals("<org.json.JSONObject: void <init>(java.util.Map)>")) {
            HashSet<Map> currentArguments = SimulationUtil.getMap(expr.getArg(0), currentValues);
            HashSet<JSONObject> finalResult = new HashSet<>();
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONObject(x));
                    } else {
                        finalResult.add(new JSONObject());
                    }
                }catch (JSONException e) {
                    finalResult.add(new JSONObject());
                }
            });
            return finalResult;
        } else if (signature.startsWith("<org.json.JSONObject: void <init>(java.lang.Object,")) {
            HashSet<Object> currentArguments = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            if (currentArguments.size() == 0) {
                currentArguments.add(new JSONObject().put("FromNotReconstructedObject", true));
            }
            HashSet<JSONObject> finalResult = new HashSet<>();
            currentArguments.forEach(x -> {
                try {
                    if (x != null) {
                        finalResult.add(new JSONObject(x));
                    } else {
                        finalResult.add(new JSONObject());
                    }
                }catch (JSONException e) {
                    finalResult.add(new JSONObject());
                }
            });
            return finalResult;
        } else if (signature.equals("<org.json.JSONObject: void <init>(java.lang.String)>")) {
            HashSet<String> currentArguments = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            HashSet<JSONObject> finalResult = new HashSet<>();
            currentArguments.forEach(x -> {
                if (x != null) {
                    try {
                        finalResult.add(new JSONObject(x));
                    } catch (JSONException e) {
                        LOGGER.error("Could not create JSONObject with: {}", x);
                    }
                } else {
                    finalResult.add(new JSONObject());
                }
            });
            return finalResult;
        } else if (signature.startsWith("<org.json.JSONObject: void <init>(")) {
            if (expr.getArgCount() >= 1) {
                HashSet<Object> currentArguments = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
                if (currentArguments.size() == 0) {
                    currentArguments.add(new JSONObject().put("FromNotReconstructedObject", true));
                }
                HashSet<JSONObject> finalResult = new HashSet<>();
                currentArguments.forEach(x -> {
                    try {

                        if (x != null) {
                            finalResult.add(new JSONObject(x));
                        } else {
                            finalResult.add(new JSONObject());
                        }
                    } catch (JSONException e) {
                        finalResult.add(new JSONObject());
                    }
                });
                return finalResult;
            }
            HashSet<JSONObject> finalResult = new HashSet<>();
            finalResult.add(new JSONObject());
            return finalResult;
        }
        return executeFunction(signature, expr, true, currentValues);
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<org.json")) {
            return null;
        }

        return executeFunction(signature, expr, false, currentValues);
    }


    private HashSet<?> executeFunction(String signature, InvokeExpr expr, boolean returnBase, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<JSONObject> result = new HashSet<>();
        if (signature.contains("<org.json.XML: org.json.JSONObject toJSONObject(java.lang.String")) {
            HashSet<String> stringArgument = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            for (String s : stringArgument) {
                result.add(org.json.XML.toJSONObject(s));
            }
        } else if (signature.equals("<org.json.Property: org.json.JSONObject toJSONObject(java.util.Properties)>")) {
            HashSet<Properties> stringArgument = SimulationUtil.getJavaProperties(expr.getArg(0), currentValues);
            for (Properties s : stringArgument) {
                if (s != null) {
                    result.add(org.json.Property.toJSONObject(s));
                }
            }
        } else if (signature.equals("<org.json.Property: org.json.JSONObject toJSONObject(org.json.JSONObject)>")) {
            HashSet<JSONObject> stringArgument = SimulationUtil.getJSONObjects(expr.getArg(0), currentValues);
            HashSet<Properties> propertiesResult = new HashSet<>();
            for (JSONObject s : stringArgument) {
                if (s != null) {
                    propertiesResult.add(org.json.Property.toProperties(s));
                }
            }
            return propertiesResult;
        } else if (signature.startsWith("<org.json.JSONML: org.json.JSONArray toJSONArray(java.lang.String")) {
            HashSet<String> stringArgument = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            HashSet<JSONArray> jsonArrayResults = new HashSet<>();
            for (String s : stringArgument) {
                jsonArrayResults.add(org.json.JSONML.toJSONArray(s));
            }
            return jsonArrayResults;
        } else if (signature.startsWith("<org.json.JSONML: org.json.JSONObject toJSONObject(java.lang.String")) {
            HashSet<String> stringArgument = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            for (String s : stringArgument) {
                result.add(org.json.JSONML.toJSONObject(s));
            }
        } else if (signature.equals("<org.json.JSONML: java.lang.String toString(org.json.JSONArray)>")) {
            HashSet<JSONArray> stringArgument = SimulationUtil.getJSONArrays(expr.getArg(0), currentValues);
            HashSet<String> stringResult = new HashSet<>();
            for (JSONArray s : stringArgument) {
                stringResult.add(org.json.JSONML.toString(s));
            }
            return stringResult;
        } else if (signature.equals("<org.json.JSONML: java.lang.String toString(org.json.JSONObject)>")) {
            HashSet<JSONObject> stringArgument = SimulationUtil.getJSONObjects(expr.getArg(0), currentValues);
            HashSet<String> stringResult = new HashSet<>();
            for (JSONObject s : stringArgument) {
                stringResult.add(org.json.JSONML.toString(s));
            }
            return stringResult;
        } else if (signature.startsWith("<org.json.JSONArray: org.json.JSONArray put")) {
            HashSet<JSONArray> jsonArrayResult = new HashSet<>();
            HashSet<JSONArray> base = SimulationUtil.getJSONArrays(((InstanceInvokeExpr) expr).getBase(), currentValues);
            if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(boolean)>")) {
                HashSet<Boolean> arg0 = SimulationUtil.getBoolean(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));
            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(java.util.Collection)>")) {
                HashSet<Collection> arg0 = SimulationUtil.getCollection(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));
            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(double)>")) {
                HashSet<Double> arg0 = SimulationUtil.getDoubleContent(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));
            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(float)>")) {
                HashSet<Float> arg0 = SimulationUtil.getFloatContent(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int)>")) {
                HashSet<Integer> arg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,boolean)>")) {
                HashSet<Float> arg1 = SimulationUtil.getFloatContent(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,java.util.Collection)>")) {
                HashSet<Collection> arg1 = SimulationUtil.getCollection(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,double)>")) {
                HashSet<Double> arg1 = SimulationUtil.getDoubleContent(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,float)>")) {
                HashSet<Float> arg1 = SimulationUtil.getFloatContent(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,int)>")) {
                HashSet<Integer> arg1 = SimulationUtil.getIntContent(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,long)>")) {
                HashSet<Long> arg1 = SimulationUtil.getLongContent(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,java.util.Map)>")) {
                HashSet<Map> arg1 = SimulationUtil.getMap(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(int,java.lang.Object)>")) {
                HashSet<Object> arg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
                base.forEach(x -> arg1.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(long)>")) {
                HashSet<Long> arg0 = SimulationUtil.getLongContent(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(java.util.Map)>")) {
                HashSet<Map> arg0 = SimulationUtil.getMap(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));

            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(java.lang.Object)>")) {
                HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.put(y))));
            }
            return jsonArrayResult;

        } else if (signature.startsWith("<org.json.JSONArray: org.json.JSONArray putAll")) {
            HashSet<JSONArray> jsonArrayResult = new HashSet<>();
            HashSet<JSONArray> base = SimulationUtil.getJSONArrays(((InstanceInvokeExpr) expr).getBase(), currentValues);
            if (signature.equals("<org.json.JSONArray: org.json.JSONArray putAll(java.util.Collection)>")) {
                HashSet<Collection> arg0 = SimulationUtil.getCollection(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.putAll(y))));
            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(org.json.JSONArray)>")) {
                HashSet<JSONArray> arg0 = SimulationUtil.getJSONArrays(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.putAll(y))));
            } else if (signature.equals("<org.json.JSONArray: org.json.JSONArray put(java.lang.Object)>")) {
                HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
                base.forEach(x -> arg0.forEach(y -> jsonArrayResult.add(x.putAll(y))));
            }
            return jsonArrayResult;
        } else if (signature.equals("<org.json.JSONArray: java.lang.String toString()>")) {
            HashSet<String> stringResults = new HashSet<>();
            HashSet<JSONArray> base = SimulationUtil.getJSONArrays(((InstanceInvokeExpr) expr).getBase(), currentValues);
            base.forEach(x -> stringResults.add(x.toString()));
            return stringResults;
        } else if (signature.equals("<org.json.JSONArray: java.util.List toList()>")) {
            HashSet<List> listResults = new HashSet<>();
            HashSet<JSONArray> base = SimulationUtil.getJSONArrays(((InstanceInvokeExpr) expr).getBase(), currentValues);
            base.forEach(x -> listResults.add(x.toList()));
            return listResults;
        } else if (signature.startsWith("<org.json.JSONArray:")) {
            if (expr instanceof InstanceInvokeExpr) {
                return SimulationUtil.getJSONArrays(((InstanceInvokeExpr) expr).getBase(), currentValues);
            }
        } else if (signature.startsWith("<org.json.JSONObject")) {
            HashSet<JSONObject> jsonResult = new HashSet<>();
            if (expr instanceof InstanceInvokeExpr) {
                HashSet<JSONObject> base = SimulationUtil.getJSONObjects(((InstanceInvokeExpr) expr).getBase(), currentValues);
                if (signature.equals("<org.json.JSONObject: org.json.JSONObject accumulate(java.lang.String,java.lang.Object)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Object> arg1 = new ArrayList<>(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add("");
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.accumulate(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject append(java.lang.String,java.lang.Object)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Object> arg1 = new ArrayList<>(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add("");
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.append(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,boolean)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Boolean> arg1 = new ArrayList<>(SimulationUtil.getBoolean(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(false);
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,java.util.Collection)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Collection> arg1 = new ArrayList<>(SimulationUtil.getCollection(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(new ArrayList());
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,double)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Double> arg1 = new ArrayList<>(SimulationUtil.getDoubleContent(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(0.0d);
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,float)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Float> arg1 = new ArrayList<>(SimulationUtil.getFloatContent(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(0.0f);
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,int)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Integer> arg1 = new ArrayList<>(SimulationUtil.getIntContent(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(0);
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,long)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Long> arg1 = new ArrayList<>(SimulationUtil.getLongContent(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(0L);
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,java.util.Map)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Map> arg1 = new ArrayList<>(SimulationUtil.getMap(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add(new HashMap());
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject put(java.lang.String,java.lang.Object)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Object> arg1 = new ArrayList<>(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add("");
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            try {
                                jsonResult.add(currentBase.put(arg0.get(i), arg1.get(i)));
                            }catch (JSONException e) {
                            }
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject putOnce(java.lang.String,java.lang.Object)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Object> arg1 = new ArrayList<>(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add("");
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.putOnce(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: org.json.JSONObject putOpt(java.lang.String,java.lang.Object)>")) {
                    List<String> arg0 = new ArrayList<>(SimulationUtil.getStringContent(expr.getArg(0), currentValues));
                    List<Object> arg1 = new ArrayList<>(SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues));
                    while (arg0.size() < arg1.size()) {
                        arg0.add("");
                    }
                    while (arg1.size() < arg0.size()) {
                        arg1.add("");
                    }
                    for (JSONObject currentBase : base) {
                        for (int i = 0; i < arg0.size(); i++) {
                            jsonResult.add(currentBase.putOpt(arg0.get(i), arg1.get(i)));
                        }
                    }
                } else if (signature.equals("<org.json.JSONObject: java.util.Map toMap()>")) {
                    HashSet<Map> mapResult = new HashSet<>();
                    for (JSONObject currentBase : base) {
                        mapResult.add(currentBase.toMap());
                    }
                    return mapResult;
                } else if (signature.equals("<org.json.JSONObject: java.util.String toString()>")) {
                    HashSet<String> mapResult = new HashSet<>();
                    for (JSONObject currentBase : base) {
                        mapResult.add(currentBase.toString());
                    }
                    return mapResult;
                }
            }
        }
        return result;
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
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
