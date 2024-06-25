package iotscope.forwardexec;

import iotscope.forwardexec.objectSimulation.SimulationUtil;
import iotscope.utility.ReflectionHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.StaticInvokeExpr;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.Callable;

public class ReflectionHandling implements Callable<HashSet<?>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReflectionHandling.class);

    private final HashMap<Value, HashSet<?>> currentValues;

    private HashSet<?> result;
    private InvokeExpr invokeExpr;
    private boolean returnBase;

    public ReflectionHandling(HashMap<Value, HashSet<?>> currentValues, InvokeExpr invokeExpr, boolean returnBase) {
        this.currentValues = currentValues;
        this.invokeExpr = invokeExpr;
        this.returnBase = returnBase;
    }

    public HashSet<?> getResult() {
        return result;
    }

    public HashSet<?> call() {
        try {
            result = executeInvokeExpr(this.invokeExpr, this.returnBase);
            return result;
        } catch (Throwable e) {
            return new HashSet<>();
        }
    }

    public HashSet<?> executeInvokeExpr(InvokeExpr invokeExpr, boolean returnBase) {

        try {
            SimulateEngine.executorThread = Thread.currentThread();
            Class<?> clazz = ReflectionHelper.getClass(invokeExpr.getMethod().getDeclaringClass().toString());
            Value base = null;
            if (invokeExpr instanceof InstanceInvokeExpr) {
                base = ((InstanceInvokeExpr) invokeExpr).getBase();
            }

            if (clazz != null) {
                if (invokeExpr.getMethod().isConstructor()) {
                    return handleInvokeConstructor(clazz, invokeExpr, base);
                } else {
                    return handleInvokeMethod(clazz, invokeExpr, returnBase, base);
                }

            }
        } catch( Throwable e) {
            LOGGER.error("Could not executeInvokeExpr: {}", e.getLocalizedMessage());
        }
        return new HashSet<>();
    }


    private HashSet<?> handleInvokeConstructor(Class<?> clazz, InvokeExpr invokeExpr, Value base) {
        HashSet<Object> result = new HashSet<>();
        Constructor<?> m = ReflectionHelper.findMatchingConstructor(clazz, invokeExpr);
        if (m == null) {
            return result;
        }
        if (base != null) {
            List<HashSet<Object>> args = new ArrayList<>();
            List<Class<?>> classesArg = new ArrayList<>();
            for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                args.add(SimulationUtil.getObjectOrConstant(invokeExpr.getArg(i), currentValues));
                classesArg.add(getClassFromString(invokeExpr.getArg(i).getType().toString()));
            }
            List<List<Object>> preparedArgs = ReflectionHelper.alignArguments(classesArg, args.toArray(new HashSet<?>[0]));
            try {
                Object returnValue;
                if (m.getParameterCount() == 0) {
                    returnValue = m.newInstance();
                    result.add(returnValue);
                } else {
                    for (List<Object> current : preparedArgs) {
                        try {
                            returnValue = m.newInstance(current.toArray());
                            result.add(returnValue);
                        } catch (Throwable e) {
                            LOGGER.error("Could not create the new object: {}", e.getLocalizedMessage());
                        }
                    }
                }
            } catch (Throwable e) {
                LOGGER.error("Could not create the new object: {}", e.getLocalizedMessage());
            }
        }
        return result;
    }


    private Class<?> getClassFromString(String clazzString) {
        if (clazzString.startsWith("byte")) {
            if (clazzString.endsWith("[]")) {
                return byte[].class;
            }
            return byte.class;
        } else if (clazzString.startsWith("int")) {
            if (clazzString.endsWith("[]")) {
                return int[].class;
            }
            return int.class;
        } else if (clazzString.startsWith("char")) {
            if (clazzString.endsWith("[]")) {
                return char[].class;
            }
            return char.class;
        } else if (clazzString.startsWith("long")) {
            if (clazzString.endsWith("[]")) {
                return long[].class;
            }
            return long.class;
        } else if (clazzString.startsWith("double")) {
            if (clazzString.endsWith("[]")) {
                return double[].class;
            }
            return double.class;
        } else if (clazzString.startsWith("float")) {
            if (clazzString.endsWith("[]")) {
                return float[].class;
            }
            return float.class;
        }
        return ReflectionHelper.getClass(clazzString);
    }


    /**
     * Handle invoke method with reflection
     *
     * @param clazz      loaded class
     * @param invokeExpr to handle
     * @param returnBase true if it is not an assignment stmt
     * @param base       of the invoked method
     * @return result of the operation
     */
    private HashSet<?> handleInvokeMethod(Class<?> clazz, InvokeExpr invokeExpr, boolean returnBase, Value base) {
        HashSet<Object> result = new HashSet<>();
        Method m = ReflectionHelper.findMatchingMethod(clazz, invokeExpr);
        if (m == null) {
            return result;
        }

        if (base != null) {//not a static invoke expr
            HashSet<Object> currentBaseObject = SimulationUtil.getObjectOrConstant(base, currentValues);

            if (currentBaseObject != null) {
                if (currentBaseObject.size() == 0) {
                    //create object by default constructor or other default values
                    Object object = ReflectionHelper.createDefaultObject(clazz);
                    if (object == null) {
                        return new HashSet<>();
                    }
                    try {
                        currentBaseObject.add(object);
                    } catch (Throwable e) {
                        LOGGER.error("Could not add {}", object);
                        return new HashSet<>();
                    }
                }
                //align arguments
                List<HashSet<Object>> args = new ArrayList<>();
                List<Class<?>> classesArg = new ArrayList<>();

                for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                    args.add(SimulationUtil.getObjectOrConstant(invokeExpr.getArg(i), currentValues));
                    classesArg.add(getClassFromString(invokeExpr.getArg(i).getType().toString()));
                }

                List<List<Object>> preparedArgs = ReflectionHelper.alignArguments(classesArg, args.toArray(new HashSet<?>[0]));

                List<Object> baseObjects = ReflectionHelper.alignBaseObject(currentBaseObject, preparedArgs.size(), clazz);

                //execute method
                int i = 0;
                for (Object current : baseObjects) {
                    if (current == null || !clazz.isAssignableFrom(current.getClass())) {
                        current = ReflectionHelper.createDefaultObject(clazz); //create object default constructor
                        if (current == null) {
                            continue;
                        }
                    }
                    try {
                        Object returnValue;
                        if (m.getParameterCount() == 0) {
                            returnValue = m.invoke(current);
                        } else {
                            returnValue = m.invoke(current, preparedArgs.get(i).toArray());
                        }
                        if (returnBase) {
                            if (current.getClass().isArray()) {
                                result.add(Arrays.asList((Object[]) current));
                            } else {
                                result.add(current);
                            }
                        } else {
                            if (returnValue.getClass().isArray()) {
                                result.add(Arrays.asList((Object[]) returnValue));
                            } else {
                                result.add(returnValue);
                            }
                        }
                    } catch (Throwable e) {
                        LOGGER.error("Could not execute method through reflection: "+ invokeExpr.toString());
                    }
                    i++;
                }
            }
        } else if (invokeExpr instanceof StaticInvokeExpr) {
            //align arguments
            Object[] args = new Object[m.getParameterCount()];
            for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                HashSet<Object> current = SimulationUtil.getObjectOrConstant(invokeExpr.getArg(i), currentValues);
                if (current == null || current.size() == 0 || current.iterator().next() == null || !current.iterator().next().getClass().isAssignableFrom(m.getParameterTypes()[i])) {
                    args[i] = ReflectionHelper.getDefaultObject(m.getParameterTypes()[i]);
                } else {
                    args[i] = current.iterator().next();
                }
            }
            try {
                Object returnValue;
                if (m.getParameterCount() == 0) {
                    returnValue = m.invoke(null);
                } else {
                    returnValue = m.invoke(null, args);
                }
                if (!returnBase) {
                    if (returnValue.getClass().isArray()) {
                        result.add(Arrays.asList((Object[]) returnValue));
                    } else {
                        result.add(returnValue);
                    }
                }
            } catch (Throwable e) {
                LOGGER.error("Could not execute static method through reflection");
            }
        }
        return result;
    }

}
