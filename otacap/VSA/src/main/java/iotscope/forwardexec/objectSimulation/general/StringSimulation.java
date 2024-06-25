package iotscope.forwardexec.objectSimulation.general;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import iotscope.main.ApkContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import soot.ArrayType;
import soot.CharType;
import soot.Value;
import soot.baf.WordType;
import soot.jimple.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static iotscope.forwardexec.objectSimulation.SimulationUtil.*;

public class StringSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(StringSimulation.class);
    private static String formatSpecifier = "%(\\d+\\$)?([-#+ 0,(\\<]*)?(\\d+)?(\\.\\d+)?([tT])?([a-zA-Z%])";
    private static Pattern pattern = Pattern.compile(formatSpecifier);


    public StringSimulation() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>") ||
                signature.equals("<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>") ||
                signature.equals("<java.lang.String: java.lang.String concat(java.lang.String)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), SimulationUtil.getStringContent(expr.getArg(0), currentValues), currentValues);

        } else if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(int)>") ) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), SimulationUtil.getStringContentFromInt(expr.getArg(0), currentValues), currentValues);
        } else if (signature.equals("<java.lang.StringBuilder: void <init>(java.lang.String)>") || signature.equals("<java.lang.StringBuffer: void <init>(java.lang.String)>") || signature.equals("<java.lang.StringBuffer: void <init>(java.lang.CharSequence)>")) {
            return transferValuesAndAppend(stmt, ((SpecialInvokeExpr) expr).getBase(), SimulationUtil.getStringContent(expr.getArg(0), currentValues), currentValues);
        } else if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(char)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), getStringSetFromChar(SimulationUtil.getCharContent(expr.getArg(0), currentValues)), currentValues);
        } else if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.Object)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), getStringFromObject(expr.getArg(0), currentValues), currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        Value leftOperation = stmt.getLeftOp();
        HashSet<String> result = new HashSet<>();

        if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>") ||
                signature.equals("<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), getStringContent(expr.getArg(0), currentValues), currentValues);
        } else if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(char)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), getStringSetFromInteger(getIntContent(expr.getArg(0), currentValues)), currentValues);
        } else if (signature.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(int)>")) {
            return transferValuesAndAppend(stmt, ((VirtualInvokeExpr) expr).getBase(), getStringSetFromChar(getCharContent(expr.getArg(0), currentValues)), currentValues);

        } else if (signature.equals("<android.content.Context: java.lang.String getString(int)>") || signature.equals("<android.content.res.Resources: java.lang.String getString(int)>")) {
            HashSet<Integer> arg0Values = SimulationUtil.getIntContent(expr.getArg(0), currentValues);
            try {
                for (int i : arg0Values) {
                    result.add(ApkContext.getInstance().findResource(i));
                }
            } catch (ClassCastException e) {
                LOGGER.error("Wrong type for {} {}", expr.getArg(0), currentValues.get(expr.getArg(0)));
            }
        } else if (signature.contains("java.lang.String toString()>") || signature.contains("<java.lang.String: java.lang.String toLowerCase(") ||
                signature.contains("<java.lang.String: java.lang.String toUpperCase(")) {
            if (expr instanceof VirtualInvokeExpr) {
                result = SimulationUtil.getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues);
            }
        } else if (signature.equals("<java.lang.String: java.lang.String trim()>")) {
            result = SimulationUtil.getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues);
        } else if (signature.equals("<android.content.Context: java.lang.String getPackageName()>")) {
            result.add(ApkContext.getInstance().getPackageName());
        } else if (signature.equals("<java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])>")) {
            return stringFormat(getStringContent(expr.getArg(0), currentValues), expr.getArg(1), leftOperation, currentValues);
        } else if (signature.equals("<java.lang.String: java.lang.String substring(int,int)>")) {
            for (Integer i1 : getIntContent(expr.getArg(0), currentValues)) {
                for (Integer i2 : getIntContent(expr.getArg(1), currentValues)) {
                    for (String s : getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues)) {
                        if (s.length() == 0) {
                            LOGGER.debug("Can't get substring of an empty string");
                            continue;
                        }
                        if (i1 >= 0 && i1 < i2 && i2 < s.length()) {
                            result.add(s.substring(i1, i2));
                        } else {
                            LOGGER.debug("index {} or {} is out of bound of the string {}", i1, i2, s);
                            result.add(s);
                        }
                    }
                }
            }

        } else if (signature.equals("<java.lang.String: java.lang.String substring(int)>")) {
            for (Integer i1 : getIntContent(expr.getArg(0), currentValues)) {
                // left side gets cleared and substring value added
                for (String s : getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues)) {
                    try {
                        result.add(s.substring(i1));
                    } catch (StringIndexOutOfBoundsException e) {
                        LOGGER.error("Integer for computing the substring is out of bound {}, {}", i1, s);
                        //better to add the whole string than loose it
                        result.add(s);
                    }
                }
            }
        } else if (signature.equals("<java.lang.String: java.lang.String replace(char,char)>")) {
            //: previous compared string was: <java.lang.String:replace(char oldChar, char newChar)> ???
            Set<Character> arg0 = getCharContent(expr.getArg(0), currentValues);
            Set<Character> arg1 = getCharContent(expr.getArg(1), currentValues);
            Set<String> base = getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues);
            int max = Math.max(Math.max(arg0.size(), arg1.size()), base.size());
            if (arg1.size() < max) {
                for (int i = 0; i < max - arg1.size(); i++) {
                    arg1.add(' ');
                }
            }

            if (arg0.size() < max) {
                for (int i = 0; i < max - arg0.size(); i++) {
                    arg0.add(' ');
                }
            }

            if (base.size() < max) {
                for (int i = 0; i < max - base.size(); i++) {
                    base.add("");
                }
            }

            for (Character s1 : arg0) {
                for (Character s2 : arg1) {
                    // left side gets cleared and substring value added
                    for (String sb : base) {
                        if (s1 != null && s2 != null && sb != null && sb.length() > 0) {
                            result.add(sb.replace(s1, s2));
                        } else if (sb != null && sb.length() > 0) {
                            result.add(sb);
                        } else {
                            result.add(String.valueOf(s2));
                        }
                    }
                }
            }
        } else if (signature.contains("<java.lang.String: java.lang.String replace")) {
            Set<String> arg0 = getStringContent(expr.getArg(0), currentValues);
            Set<String> arg1 = getStringContent(expr.getArg(1), currentValues);
            Set<String> base = getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues);
            int max = Math.max(Math.max(arg0.size(), arg1.size()), base.size());
            if (arg1.size() < max) {
                for (int i = 0; i < max - arg1.size(); i++) {
                    arg1.add("");
                }
            }

            if (arg0.size() < max) {
                for (int i = 0; i < max - arg0.size(); i++) {
                    arg0.add("");
                }
            }

            if (base.size() < max) {
                for (int i = 0; i < max - base.size(); i++) {
                    base.add("");
                }
            }

            for (String s1 : arg0) {
                for (String s2 : arg1) {
                    // left side gets cleared and substring value added
                    for (String sb : base) {
                        if (s1 != null && s2 != null && sb != null && sb.length() > 0 && s1.length() > 0) {
                            result.add(sb.replace(s1, s2));
                        } else if (sb != null && sb.length() > 0) {
                            result.add(sb);
                        } else {
                            result.add(s2);
                        }
                    }
                }
            }
        } else if (signature.equals("<java.lang.String: java.lang.String format(java.util.Locale,java.lang.String,java.lang.Object[])>")) {
            return stringFormat(getStringContent(expr.getArg(1), currentValues), expr.getArg(2), leftOperation, currentValues);

        } else if (signature.contains("<java.lang.String: java.lang.String[] split(java.lang.String")) {
            HashSet<ArrayList<String>> strings = new HashSet<>();
            Set<String> arg0 = getStringContent(expr.getArg(0), currentValues);
            Set<String> base = getStringContent(((VirtualInvokeExpr) expr).getBase(), currentValues);
            if (arg0.size() < base.size()) {
                for (int i = 0; i < base.size() - arg0.size(); i++) {
                    arg0.add("");
                }
            }
            for (String b : base) {
                for (String arg : arg0) {
                    strings.add(new ArrayList<>(Arrays.asList(b.split(arg))));
                }
            }
            return strings;
        } else if (signature.contains("<java.net.URLEncoder: java.lang.String encode(")) {
            return SimulationUtil.getStringContent(expr.getArg(0), currentValues);
        } else if (signature.contains("<java.lang.String: char[] toCharArray(")) {
            return toCharaArray(SimulationUtil.getStringContent(((InstanceInvokeExpr) expr).getBase(), currentValues));
        }
        return result;
    }


    public HashSet<?> toCharaArray(HashSet<String> base) {
        HashSet<List<Character>> result = new HashSet<>();
        for (String s : base) {
            List<Character> current = new ArrayList<>();
            if (s != null) {
                for (char c : s.toCharArray()) {
                    current.add(c);
                }
            }
            result.add(current);
        }
        return result;
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.getType().toString().equals("java.lang.StringBuilder") || rightValue.getType().toString().equals("java.lang.StringBuffer")) {
            return setInitValue(stmt.getLeftOp(), "", false, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue instanceof StringConstant) {
            return setInitValue(leftOp, ((StringConstant) rightValue).value, false, currentValues);
        }
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType() instanceof CharType || newArrayExpr.getBaseType() instanceof WordType) {
            return setInitValue(stmt.getLeftOp(), ((NewArrayExpr) rightValue).getSize() + "", false, currentValues);
        } else if (newArrayExpr.getBaseType().toString().equals("java.lang.String")) {
            return SimulationUtil.initArray("", newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    private HashSet<String> transferValuesAndAppend(Stmt stmt, Value from, HashSet<String> appends, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> currentValuesFrom = getStringContent(from, currentValues);
        if (currentValuesFrom.size() == 0) {
            currentValuesFrom = new HashSet<>();
            currentValuesFrom.add("");
        }

        if (appends.size() == 0) {
            LOGGER.warn(String.format("[%s] [SIMULATE][transferValuesAndAppend arg unknown]: %s", this.hashCode(), stmt));
            appends = new HashSet<>();
            appends.add("[NULL]");
            //return;
        } //

        HashSet<String> newValues = new HashSet<>();
        for (String append : appends) {
            for (String str : currentValuesFrom) {
                if (append == null || str == null || newValues.size() >= 7000) {
                    continue;
                }
                if (append.startsWith("&") && str.contains(append)) {
                    LOGGER.debug("Do not append {}, because {} already contains it", append, str);
                    continue;
                }
                if (str.length() < 7000 && append.length() < 7000) {
                    newValues.add(str + append);
                } else if (append.length() < 7000) {
                    newValues.add(append);
                } else {
                    int min = Math.min(str.length(), 7000);
                    newValues.add(str.substring(0, min));
                }
            }
        }

        return (HashSet<String>) newValues.clone();

    }


    private HashSet<String> getStringSetFromChar(HashSet<Character> characters) {
        HashSet<String> result = new HashSet<>();
        characters.forEach(x -> result.add(String.valueOf(x)));
        return result;
    }

    private HashSet<String> getStringSetFromInteger(HashSet<Integer> integers) {
        HashSet<String> result = new HashSet<>();
        integers.forEach(x -> result.add(String.valueOf(x)));
        return result;
    }

    // e.g., using array as the append argument
    private HashSet<String> getStringFromObject(Value value, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> result = new HashSet<>();

        if (value.getType() instanceof ArrayType) {
            currentValues.forEach((key, content) -> {
                if(key.equals(value)){
                    for(Object item : content) {

                        String oneResult = "";

                        if (item instanceof ArrayList<?>) {
                            ArrayList<?> innerList = (ArrayList<?>) item;
                            for (Object innerItem : innerList) {
                                oneResult += innerItem + "";
                            }
                        }

                        result.add(oneResult);
                    }     
                }
            });
            return result;
        }            

        else {
            return getObjects(value, currentValues, String.class, "");
        }
    }


    public HashSet<?> setInitValue(Value leftValue, String str, boolean append, HashMap<Value, HashSet<?>> currentValues) {

        HashSet<String> stringContent = SimulationUtil.getStringContent(leftValue, currentValues);
        if (!append) {
            stringContent.clear();
        }
        stringContent.add(str);
        return stringContent;
    }

    private int getMatchingCount(String s) {
        int result = 0;
        Matcher matcher = pattern.matcher(s);
        while (matcher.find()) {
            result++;
        }
        return result;
    }

    private HashSet<String> stringFormat(HashSet<String> stringFormat, Value arg1, Value leftOperation, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<String> result = new HashSet<>();
        int max = 0;
        for (String s : stringFormat) {
            max = Math.max(max, getMatchingCount(s));
        }
        List<String> array = SimulationUtil.getSimulatedArrayOrInit(arg1, max, arg1, currentValues);
        for (String s : stringFormat) {
            Object[] toFormat = alignFormatObjectArray(array.toArray(new String[max]), s);
            try {
                result.add(String.format(s, toFormat));
            } catch (IllegalFormatConversionException e) {
                //Fallback case, to avoid missing the string entirely
                result.add(String.format(s, new Object[max]));
            } catch (UnknownFormatConversionException e) {
                StringBuilder toAdd = new StringBuilder(s);
                for (Object o : toFormat) {
                    if (o != null) {
                        toAdd.append(o);
                    }

                }
                result.add(toAdd.toString());
            }
        }
        return result;
    }

    private Object[] alignFormatObjectArray(String[] formatArray, String formatString) {
        Object[] result = new Object[formatArray.length];
        Matcher matcher = pattern.matcher(formatString);
        int i = 0;
        while (matcher.find()) {
            String matchingGroup = matcher.group();
            switch (matchingGroup.charAt(matchingGroup.length() - 1)) {
                case 'o':
                case 'x':
                case 'd':
                    long currentLong = -1L;
                    try {
                        currentLong = Long.parseLong(formatArray[i]);
                    } catch (NumberFormatException | NullPointerException e) {
                        LOGGER.debug(e.fillInStackTrace().toString());
                    }
                    result[i] = currentLong;
                    break;
                case 'e':
                case 'a':
                case 'g':
                case 'f':
                    Float currentFloat = null;
                    try {
                        currentFloat = Float.valueOf(formatArray[i]);
                    } catch (NumberFormatException | NullPointerException e) {
                        LOGGER.debug(e.fillInStackTrace().toString());
                    }
                    result[i] = currentFloat;
                    break;
                case 'n':
                    i--;
                    break;
                case 'c':
                    if (formatArray[i] != null && formatArray[i].length() > 0) {
                        result[i] = formatArray[i].charAt(0);
                    }
                    break;
                case 'h':
                case 'b':
                case 's':
                    result[i] = formatArray[i];
                    break;
                case 't':
                default:
                    result[i] = null;
                    break;

            }
            i = i + 1;

        }
        return result;

    }


}
