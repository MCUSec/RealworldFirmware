package iotscope.forwardexec.objectSimulation.json;

import com.google.gson.*;
import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.HashMap;
import java.util.HashSet;

public class GoogleGsonSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(GoogleGsonSimulation.class);


    public GoogleGsonSimulation() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<com.google.gson")) {
            return null;
        }
        if (signature.equals("<com.google.gson.Gson: void <init>()>")) {
            HashSet<Gson> result = new HashSet<>();
            result.add(new Gson());
            return result;
        } else if (signature.startsWith("<com.google.gson.JsonArray: void <init>(>")) {
            HashSet<JsonArray> result = new HashSet<>();
            result.add(new JsonArray());
            return result;
        } else if (signature.equals("<com.google.gson.JsonObject: void <init>()>")) {
            HashSet<JsonObject> result = new HashSet<>();
            result.add(new JsonObject());
            return result;
        } else if (signature.startsWith("<com.google.gson.JsonArray:")) {
            // all add functions
            HashSet<JsonArray> result = new HashSet<>();
            HashSet<JsonArray> base = SimulationUtil.getJsonArrayContent(((InstanceInvokeExpr) expr).getBase(), currentValues);

            if (signature.equals("<com.google.gson.JsonArray: void add(java.lang.Boolean)>")) {
                HashSet<Boolean> arg0 = SimulationUtil.getBoolean(expr.getArg(0), currentValues);
                for (JsonArray currentBase : base) {
                    for (Boolean currentArg : arg0) {
                        currentBase.add(currentArg);
                    }
                    result.add(currentBase);
                }
            } else if (signature.equals("<com.google.gson.JsonArray: void add(java.lang.Character)>")) {
                HashSet<Character> arg0 = SimulationUtil.getCharContent(expr.getArg(0), currentValues);
                for (JsonArray currentBase : base) {
                    for (Character currentArg : arg0) {
                        currentBase.add(currentArg);
                    }
                    result.add(currentBase);
                }
            } else if (signature.equals("<com.google.gson.JsonArray: void add(java.lang.Number)>")) {

            } else if (signature.equals("<com.google.gson.JsonArray: void add(java.lang.String)>")) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                for (JsonArray currentBase : base) {
                    for (String currentArg : arg0) {
                        currentBase.add(currentArg);
                    }
                    result.add(currentBase);
                }
            } else if (signature.equals("<com.google.gson.JsonArray: void add(com.google.gson.JsonArray)>")) {
                HashSet<JsonArray> arg0 = SimulationUtil.getJsonArrayContent(expr.getArg(0), currentValues);
                for (JsonArray currentBase : base) {
                    for (JsonArray currentArg : arg0) {
                        currentBase.add(currentArg);
                    }
                    result.add(currentBase);
                }
            }

        }else if (signature.contains("void toJson(com.google.gson.JsonElement")) {
            HashSet<String> result = new HashSet<>();
            Gson gson = new Gson();
            HashSet<JsonElement> arg0 = SimulationUtil.getJsonElementContent(expr.getArg(0) ,currentValues);
            arg0.forEach(x-> result.add(gson.toJson(x)));
            currentValues.put(expr.getArg(1), result);
        } else if (signature.contains("void toJson(java.lang.Object")) {
            HashSet<String> result = new HashSet<>();
            Gson gson = new Gson();
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0) ,currentValues);
            arg0.forEach(x-> result.add(gson.toJson(x)));
            if (result.size() == 0) {
                result.add("{\"from\": \"gsonJsonObject\"}");
            }
            currentValues.put(expr.getArg(1), result);
        }
        return executeFunction(signature, expr, true, currentValues);
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (!signature.startsWith("<com.google.gson")) {
            return null;
        }

        if (signature.startsWith("<com.google.gson.JsonParser")) {
            HashSet<JsonElement> result = new HashSet<>();
            if (signature.equals("<com.google.gson.JsonParser: com.google.gson.JsonElement parse(java.lang.String)>") ||
                    signature.equals("<com.google.gson.JsonParser: com.google.gson.JsonElement parseString(java.lang.String)>")) {
                HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                arg0.forEach(x -> result.add(JsonParser.parseString(x)));
                return result;
            }
        } else if (signature.equals("<com.google.gson.JsonElement: java.lang.String toString()>")) {
            HashSet<JsonElement> elements = SimulationUtil.getJsonElementContent(((InstanceInvokeExpr) expr).getBase(), currentValues);
            HashSet<String> results = new HashSet<>();

            elements.forEach(x -> results.add(x.toString()));
            return results;
        } else if (signature.startsWith("<com.google.gson.JsonArray")) {
            if (signature.contains("get")) {
                HashSet<JsonArray> base = SimulationUtil.getJsonArrayContent(((InstanceInvokeExpr) expr).getBase(), currentValues);
                if (signature.equals("<com.google.gson.JsonArray: com.google.gson.JsonElement get(int)>")) {
                    HashSet<JsonElement> result = new HashSet<>();
                    HashSet<Integer> arg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                    for (JsonArray currentArray : base) {
                        for (Integer currentArg : arg0) {
                            result.add(currentArray.get(currentArg));
                        }
                    }
                    return result;

                } else if (signature.equals("<com.google.gson.JsonArray: boolean getAsBoolean()>")) {
                    HashSet<Boolean> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsBoolean()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: byte getAsByte()>")) {
                    HashSet<Byte> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsByte()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: char getAsCharacter()>")) {
                    HashSet<Character> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsCharacter()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: float getAsFloat()>") ||
                        signature.equals("<com.google.gson.JsonArray: java.math.BigDecimal getAsBigDecimal()>")) {
                    HashSet<Float> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsFloat()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: int getAsInt()>") ||
                        signature.equals("<com.google.gson.JsonArray: java.math.BigInteger getAsBigInteger()>")) {
                    HashSet<Integer> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsInt()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: long getAsLong()>")) {
                    HashSet<Long> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsLong()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: java.lang.Number getAsNumber()>")) {
                    HashSet<Number> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsNumber()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: short getAsShort()>")) {
                    HashSet<Short> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsShort()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: java.lang.String getAsString()>")) {
                    HashSet<String> result = new HashSet<>();
                    base.forEach(x -> result.add(x.getAsString()));
                    return result;
                } else if (signature.equals("<com.google.gson.JsonArray: java.lang.String toString()>")) {
                    HashSet<String> result = new HashSet<>();
                    base.forEach(x -> result.add(x.toString()));
                    return result;
                }
            }
        } else if (signature.startsWith("<com.google.gson.Gson:")) {
            HashSet<String> result = new HashSet<>();
            Gson gson = new Gson();
            if (signature.contains("fromJson")) {
                result.add("fromGsonJson");
            } else if (signature.contains("java.lang.String toJson(com.google.gson.JsonElement")){
                HashSet<JsonElement> arg0 = SimulationUtil.getJsonElementContent(expr.getArg(0) ,currentValues);
                arg0.forEach(x-> result.add(gson.toJson(x)));
            } else if (signature.contains("java.lang.String toJson(java.lang.Object")){
                HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0) ,currentValues);
                arg0.forEach(x-> result.add(gson.toJson(x)));
                if (result.size() == 0) {
                    result.add("{\"from\": \"gsonJsonObject\"}");
                }
            }

                return result;
        }
        return executeFunction(signature, expr, false, currentValues);
    }


    private HashSet<?> executeFunction(String signature, InvokeExpr expr, boolean returnBase, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.startsWith("<com.google.gson.JsonArray")) {
            HashSet<JsonArray> jsonArray = SimulationUtil.getJsonArrayContent(((InstanceInvokeExpr) expr).getBase(), currentValues);
            //remove functions
            //set functions
            if (signature.equals("<com.google.gson.JsonArray: com.google.gson.JsonElement remove(int)>")) {
                HashSet<JsonElement> result = new HashSet<>();
                HashSet<Integer> arg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                jsonArray.forEach(x -> arg0.forEach(y -> {
                    try {result.add(x.remove(y));}
                    catch (Exception e) {
                        //we can't do anything
                    }
                }));
                if (!returnBase) {
                    return result;
                }
            } else if (signature.equals("<com.google.gson.JsonArray: boolean remove(com.google.gson.JsonElement)>")) {
                HashSet<Boolean> result = new HashSet<>();
                HashSet<JsonElement> arg0 = SimulationUtil.getJsonElementContent(expr.getArg(0), currentValues);
                jsonArray.forEach(x -> arg0.forEach(y -> {
                    try {result.add(x.remove(y));}
                    catch (Exception e) {
                        //we can't do anything
                    }
                }));
                if (!returnBase) {
                    return result;
                }
            } else if (signature.equals("<com.google.gson.JsonArray: com.google.gson.JsonElement set(int,com.google.gson.JsonElement)>")) {
                HashSet<JsonElement> result = new HashSet<>();
                HashSet<Integer> arg0 = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
                HashSet<JsonElement> arg1 = SimulationUtil.getJsonElementContent(expr.getArg(1), currentValues);
                JsonElement first = arg1.iterator().next();
                jsonArray.forEach(x -> arg0.forEach(y -> result.add(x.set(y, first))));
                if (!returnBase) {
                    return result;
                }
            }
            if (returnBase) {
                return jsonArray;
            }
        }
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
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }


}
