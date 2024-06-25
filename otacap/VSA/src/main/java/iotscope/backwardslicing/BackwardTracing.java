package iotscope.backwardslicing;

import org.json.JSONObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class BackwardTracing {
    private static String RULE_TAINT_KEY = "taint";
    private static String RULE_TAINT_BASENAME = "base";
    private static String RULE_TAINT_ALLARGS = "args";
    private static String RULE_TAINT_ARGS_PRE = "arg";
    private static String RULE_TAINT_IS_SYS_API_SRC = "isSystemAPISrc";
    private static String RULE_EXCEPT_ARGUMENT = "except";

    public BackwardTracing(String path) {
        String jsonRules = null;
        try {
            jsonRules = new String(Files.readAllBytes(Paths.get(path)));
        } catch (IOException e) {
            System.err.println("TaintRules load error!");
            e.printStackTrace();
            System.exit(0);
        }

        JSONObject jsonRuleObject = new JSONObject(jsonRules);

        for (String key : jsonRuleObject.keySet()) {
            String[] splitSignature = splitSignature(key);
            BackwardRule currentRule = new BackwardRule();
            List<Object> ts = jsonRuleObject.getJSONObject(key).getJSONArray(RULE_TAINT_KEY).toList();
            currentRule.setTaintAll(ts.contains(RULE_TAINT_ALLARGS));
            currentRule.setBaseInteresting(ts.contains(RULE_TAINT_BASENAME));

            if (jsonRuleObject.getJSONObject(key).has(RULE_TAINT_IS_SYS_API_SRC)) {
                currentRule.setSysApiSrc((List<String>) (Object) jsonRuleObject.getJSONObject(key).getJSONArray(RULE_TAINT_IS_SYS_API_SRC).toList());
            }

            if (jsonRuleObject.getJSONObject(key).has(RULE_EXCEPT_ARGUMENT)) {
                currentRule.setExcept((List<String>) (Object) jsonRuleObject.getJSONObject(key).getJSONArray(RULE_EXCEPT_ARGUMENT).toList());
            }
            List<Integer> argList = new LinkedList<>();
            for (Object o : ts) {
                if (!o.equals(RULE_TAINT_ALLARGS) && ((String) o).contains(RULE_TAINT_ARGS_PRE)) {
                    argList.add(Integer.valueOf(((String) o).replace(RULE_TAINT_ARGS_PRE, "")));
                }
            }
            currentRule.setInterestingArgs(argList);
            Map<String, BackwardRule> argRules = new HashMap<>();
            Map<String, Map<String, BackwardRule>> methodArgs = new HashMap<>();
            Map<String, Map<String, Map<String, BackwardRule>>> returnMethod = new HashMap<>();

            Map<String, Map<String, Map<String, BackwardRule>>> returnMap = rules.get(splitSignature[0]);
            if (returnMap != null) {
                Map<String, Map<String, BackwardRule>> methodNameMap = returnMap.get(splitSignature[1]);
                if (methodNameMap != null) {
                    Map<String, BackwardRule> methodArgumentMap = methodNameMap.get(splitSignature[2]);
                    if (methodArgumentMap != null) {
                        methodArgumentMap.put(splitSignature[3], currentRule);
                    } else {
                        argRules.put(splitSignature[3], currentRule);
                        methodNameMap.put(splitSignature[2], argRules);
                    }
                } else {
                    argRules.put(splitSignature[3], currentRule);
                    methodArgs.put(splitSignature[2], argRules);
                    returnMap.put(splitSignature[1], methodArgs);
                }
            } else {
                argRules.put(splitSignature[3], currentRule);
                methodArgs.put(splitSignature[2], argRules);
                returnMethod.put(splitSignature[1], methodArgs);
                rules.put(splitSignature[0], returnMethod);
            }
        }
    }


    private static BackwardTracing backwardTracing;
    public static String PATH;
    public static void createInstance(String path) {
        PATH = path;
        backwardTracing = new BackwardTracing(path);
    }

    public static BackwardTracing getInstance() {
        if (backwardTracing == null) {
            if (PATH != null) {
                backwardTracing = new BackwardTracing(PATH);
            }else {
                backwardTracing = new BackwardTracing(ClassLoader.getSystemClassLoader().getResource("taintrules.json").getPath());
            }
        }
        return backwardTracing;
    }

    // base -> return -> signature -> arguments
    private Map<String, Map<String, Map<String, Map<String, BackwardRule>>>> rules = new HashMap<>();

    public boolean hasRuleFor(String methodSignature) {
        return getRule(methodSignature) != null;
    }

    private BackwardRule getRule(String signature) {
        List<String[]> toTest = new ArrayList<>();
        String[] signatureArray = splitSignature(signature);
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                for (int k = 0; k < 2; k++) {
                    for (int l = 0; l < 2; l++) {
                        String[] tmp = new String[4];
                        if (i == 0) {
                            tmp[0] = signatureArray[0];
                        } else {
                            tmp[0] = "*";
                        }

                        if (j == 0) {
                            tmp[1] = signatureArray[1];
                        } else {
                            tmp[1] = "*";
                        }

                        if (k == 0) {
                            tmp[2] = signatureArray[2];
                        } else {
                            tmp[2] = "*";
                        }

                        if (l == 0) {
                            tmp[3] = signatureArray[3];
                        } else {
                            tmp[3] = "*";
                        }
                        toTest.add(tmp);
                    }
                }
            }
        }

        for (String[] sig : toTest) {
            BackwardRule rule = getRule(sig);
            if (rule != null) {
                return rule;
            }
        }
        return null;
    }

    private BackwardRule getRule(String[] signatureArray) {
        Map<String, Map<String, Map<String, BackwardRule>>> returnMap = getReturnFromObject(signatureArray[0]);
        if (returnMap != null) {
            Map<String, Map<String, BackwardRule>> methodMap = getMethodFromReturn(signatureArray[1], returnMap);
            if (methodMap != null) {
                Map<String, BackwardRule> parameterMap = getParameterFromMethod(signatureArray[2], methodMap);
                if (parameterMap != null) {
                    return getRuleFromParameter(signatureArray[3], parameterMap);
                }
            }
        }
        return null;
    }


    private BackwardRule getRuleFromParameter(String signature, Map<String, BackwardRule> parameterMap) {
        return parameterMap.get(signature);
    }

    private Map<String, BackwardRule> getParameterFromMethod(String signature, Map<String, Map<String, BackwardRule>> methodMap) {
        return methodMap.get(signature);
    }

    private Map<String, Map<String, BackwardRule>> getMethodFromReturn(String signature, Map<String, Map<String, Map<String, BackwardRule>>> returnMap) {
        return returnMap.get(signature);
    }

    private Map<String, Map<String, Map<String, BackwardRule>>> getReturnFromObject(String signature) {
        return rules.get(signature);
    }

    public boolean isBaseInteresting(String methodSignature) {
        BackwardRule rule = getRule(methodSignature);
        if (rule == null) {
            return false;
        }
        return rule.isBaseInteresting();
    }


    public List<Integer> getInterestedArgIndexes(String methodSignature, int argsLen) {
        BackwardRule rule = getRule(methodSignature);
        if (rule == null) {
            return null;
        }
        if (rule.isTaintAll()) {
            List<Integer> results = new LinkedList<>();
            //iterate over breaks
            String parameters = methodSignature.substring(methodSignature.indexOf("("), methodSignature.indexOf(")"));
            String[] parameterArray = parameters.split(",");
            for (int i = 0; i < argsLen; i++) {
                if (!rule.getExcept().contains(parameterArray[i])) {
                    results.add(i);
                }
            }
            return results;
        }

        return rule.getInterestingArgs();

    }

    private String[] splitSignature(String methodSignature) {
        String[] result = new String[4];
        result[0] = methodSignature.substring(1, methodSignature.indexOf(":"));
        result[1] = methodSignature.substring(methodSignature.indexOf(":") + 2, methodSignature.indexOf(" ", methodSignature.indexOf(":") + 2));
        result[2] = methodSignature.substring(methodSignature.indexOf(" ", methodSignature.indexOf(":") + 2) + 1, methodSignature.indexOf("("));
        result[3] = methodSignature.substring(methodSignature.indexOf("(") + 1, methodSignature.indexOf(")"));
        return result;
    }



}
