package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.StringConstant;
import soot.jimple.internal.AbstractInstanceInvokeExpr;

import static iotscope.forwardexec.objectSimulation.SimulationUtil.getStringContent;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Pattern;


public class AndroidSpecificSimulation implements SimulationObjects {


    private static Pattern regex = Pattern.compile("<android\\.widget.*:.*getText\\(\\)>");
    private static final Logger LOGGER = LoggerFactory.getLogger(AndroidSpecificSimulation.class);


    public AndroidSpecificSimulation() {

    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if(signature.contains("<android.content.Intent: android.content.Intent putExtra(")) {
            HashSet results = null;
            HashSet<Object> keys = new HashSet<>();
            HashSet<?> vals = new HashSet<>();
            Value key_param = expr.getArg(0);
            Value val_param = expr.getArg(1);
            
            if (key_param instanceof Local) {
               keys = (HashSet<Object>) currentValues.get(key_param);
            } else if (key_param instanceof Constant) {
                keys.add(key_param);
            }

            if (val_param instanceof Local) {
                vals = currentValues.get(val_param);
            }

            for(Object k : keys) {
                if (k instanceof Value) {
                    currentValues.put((Value)k, vals);
                } else if (k instanceof String) {
                    StringConstant toAdd = StringConstant.v((String)k);
                    currentValues.put((Value)toAdd, vals);
                }
            }
        } 
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (regex.matcher(signature).matches()) {
            Value to = stmt.getLeftOp();

            HashSet<String> values = (HashSet<String>) currentValues.get(to);
            if (values == null) {
                values = new HashSet<>();
            }
            currentValues.remove(to);
            values.clear();
            values.add("fromUI.local");
            return values;
        }
        Value leftKey = SimulationUtil.getKeyValue(stmt.getLeftOp());

        if (signature.contains("android.view.View findViewById(int)") || signature.contains("android.view.View internalFindViewById(int)") || signature.contains(
                "android.view.LayoutInflater: android.view.View inflate(int,android.view.ViewGroup)") || signature.contains("android.view.LayoutInflater: android.view.View inflate(int,android.view.ViewGroup,boolean)")) {
            return getCorrectResult(expr.getArg(0), currentValues, stmt);

        } else if (signature.contains("android.view.View findRequiredView(java.lang.Object,int,java.lang.String)") || signature.contains(
                "butterknife.internal.Utils: java.lang.Object findRequiredViewAsType(android.view.View,int,java.lang.String,java.lang.Class)")) {
            HashSet<String> result = getCorrectResult(expr.getArg(1), currentValues, stmt);
            result.addAll(getCorrectResult(expr.getArg(2), currentValues, stmt));
            return result;
        } else if (signature.contains("android.view.View inflate(android.content.Context,int,android.view.ViewGroup)")) {
            return getCorrectResult(expr.getArg(1), currentValues, stmt);

        } else if (signature.equals("<android.content.Intent: android.os.Bundle getExtras()>")) {
            HashSet<String> result = SimulationUtil.getStringContent(((AbstractInstanceInvokeExpr) expr).getBase(), currentValues);
            result.addAll(SimulationUtil.getStringContent(leftKey, currentValues));
            result.add("Intent_GetExtra->Bundle");
            return result;
        } else if (signature.contains("<android.content.Intent") && signature.contains("get") && signature.contains("Extra")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);

            HashSet resultsFromIntent = new HashSet<>();
            for(Object a0 : arg0){

                if(a0 instanceof Value){
                    resultsFromIntent = currentValues.get(a0);
                } else if (a0 instanceof String) {
                    StringConstant toLook = StringConstant.v((String)a0);
                    resultsFromIntent = currentValues.get(toLook);
                }

                if(resultsFromIntent.size() > 0) {
                    for(Object resIntent : resultsFromIntent) {
                        if (resIntent instanceof String){
                            result.add((String)resIntent);
                        }
                    }
                    return result;
                }
            }
            String toAdd = "Intent_GetExtra" + expr.getType() + "->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("<android.os.Bundle") && signature.contains("get") && !signature.contains("getClipData")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            String toAdd = "Bundle_GetExtra" + expr.getType() + "->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.equals(
                "<android.preference.PreferenceManager: android.content.SharedPreferences getDefaultSharedPreferences(android.content.Context)>")) {
            HashSet<String> result = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            result.addAll(SimulationUtil.getStringContent(leftKey, currentValues));
            result.add("SharedPreferences_GetDefault");
            return result;
        } else if (signature.equals("<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            String toAdd = "SharedPreferences_GetString->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("<android.content.SharedPreferences") && signature.contains("getAll")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            String toAdd ="SharedPreferences_GetExtra" + expr.getType() + "->" + expr.toString();
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        }if (signature.contains("<android.content.SharedPreferences") && signature.contains("get")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            String toAdd = "SharedPreferences_GetExtra" + expr.getType() + "->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("android.database.sqlite.SQLiteDatabase") && signature.contains("open") && signature.contains("Database")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            String toAdd = "SQLiteDatabase_GetOpen->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("android.database.Cursor") && signature.contains("rawQuery") && !signature.contains("WithFactory")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg0 = SimulationUtil.getObjectOrConstant(expr.getArg(0), currentValues);
            String toAdd = "SQLiteDatabase_GetQuery->" + expr.getArg(0).toString() + " - " + Arrays.toString(arg0.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("android.database.Cursor") && signature.contains("rawQuery") && signature.contains("WithFactory")) {
            HashSet<String> result = SimulationUtil.getStringContent(leftKey, currentValues);
            HashSet<Object> arg1 = SimulationUtil.getObjectOrConstant(expr.getArg(1), currentValues);
            String toAdd = "SQLiteDatabase_GetQuery->" + expr.getArg(1).toString() + " - " + Arrays.toString(arg1.toArray());
            toAdd = toAdd.substring(0, Math.min(100, toAdd.length()));
            result.add(toAdd);
            return result;
        } else if (signature.contains("android.widget.EditText: android.text.Editable getText()") ||
                signature.contains("java.io.File: java.lang.String getName()") ||
                signature.contains("android.app.Dialog: android.view.Window getWindow()") ||
                signature.contains("android.widget.TextView: java.lang.CharSequence getText()") ||
                signature.equals("<butterknife.ButterKnife$Finder: android.view.View findOptionalView(java.lang.Object,int)>") ||
                signature.equals("<java.lang.Class: java.lang.Object cast(java.lang.Object)>") ||
                signature.equals("<android.widget.LinearLayout: android.view.View getChildAt(int)>")) {
            return SimulationUtil.getStringContent(((AbstractInstanceInvokeExpr) expr).getBase(), currentValues);
        } else if (signature.equals("<java.util.UUID: java.util.UUID fromString(java.lang.String)>")) {
            return SimulationUtil.getStringContent(expr.getArg(0), currentValues);
        } else if (signature.equals("<java.util.UUID: java.lang.String toString()>")) {
            return SimulationUtil.getStringContent(((AbstractInstanceInvokeExpr) expr).getBase(), currentValues);
        }


        return null;
    }


    private HashSet<String> getCorrectResult(Value value, HashMap<Value, HashSet<?>> currentValues, AssignStmt stmt) {
        if (value.toString().contains("$")) {
            HashSet<Integer> integerResults = SimulationUtil.getIntContent(value, currentValues);
            HashSet<String> result = new HashSet<>();
            integerResults.forEach(x -> result.add(x != null ? x.toString() : ""));
            return result;
        } else {
            HashSet<String> result = SimulationUtil.getStringContent(stmt.getLeftOp(), currentValues);
            result.add(value.toString());
            return result;
        }
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.getType().toString().contains("android.widget.EditText")) {
            HashSet<String> result = new HashSet<>();
            result.add("New<->EditText");
            return result;
        }
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