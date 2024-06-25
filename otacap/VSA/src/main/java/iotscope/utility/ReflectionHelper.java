package iotscope.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.SootField;
import soot.jimple.InvokeExpr;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;

public class ReflectionHelper {

    private static final Map<String, Class<?>> loadedClasses;
    private static final Logger LOGGER = LoggerFactory.getLogger(ReflectionHelper.class);

    public static String androidJar = null; //save the paths to retrieve them from the agent
    public static String appJar = null; //save the paths to retrieve them from the agent



    static {
        loadedClasses = new HashMap<>();
    }

    private static URLClassLoader cl = null;

    /**
     * Initialize the class loader
     *
     * @param apkPath to load classes from
     */
    public static void init(String apkPath, String androidJarPath) {
        try {
            File apkFile = new File(apkPath);
            String jarFile = apkFile.getParent() + "/jarFiles/" + apkFile.getName().replace(".apk", "-dex2jar.jar");
            androidJar = jarFile;
            appJar = androidJarPath;

            URL[] urls = {new URL("jar:file:" + jarFile + "!/"), new URL("jar:file:" + androidJarPath + "!/")};
            cl = URLClassLoader.newInstance(urls);

        } catch (Exception err) {
        }
    }

    /**
     * Load class from jar file,
     *
     * @param clazz to load
     * @return loaded class
     */
    public static Class<?> getClass(String clazz) {
        Class<?> currentClazz = loadedClasses.get(clazz);
        if (currentClazz == null) {
            if (clazz.contains("[]")) {
                return getArrayClass(clazz);
            }
            return loadClass(clazz);
        }
        return currentClazz;
    }

    /**
     * Load class from jar file
     *
     * @param clazz to load
     * @return loaded class
     */
    private static Class<?> loadClass(String clazz) {
        try {
            Class<?> c = cl.loadClass(clazz);
            loadedClasses.put(c.getName(), c);
            return c;
        } catch (Throwable err) {
            LOGGER.debug("Class loading failed with exception: {}", err.getLocalizedMessage());
        }
        return null;
    }

    private static Class<?> getArrayClass(String clazz) {
        try {
            String base = clazz.replace("[]", "");
            Class<?> baseClass = getClass(base);
            if (baseClass == null) {
                return null;
            }
            int count = (int) clazz.chars().filter(ch -> ch == '[').count();
            int[] dimensions = new int[count];
            Class<?> c = Array.newInstance(baseClass, dimensions).getClass();
            loadedClasses.put(clazz, c);
            return c;
        } catch (Throwable e) {
            LOGGER.debug("Class loading failed with exception: {}", e.getLocalizedMessage());
        }
        return null;
    }

    /**
     * Finds matching method
     *
     * @param clazz      to look for methods
     * @param invokeExpr to find matching methods
     * @return method if any match
     */
    public static Method findMatchingMethod(Class<?> clazz, InvokeExpr invokeExpr) {
        try {
            String methodName = invokeExpr.getMethod().getName();
            Method[] executables = clazz.getMethods();
            Method defaultMethod = null;

            for (Method m : executables) {
                if ((!m.getName().equals(methodName) || m.getParameterCount() != invokeExpr.getArgCount())) {
                    continue;
                }
                if (m.getParameterCount() == 0) {
                    defaultMethod = m;
                }
                if (invokeExpr.getArgCount() == m.getParameterCount()) {
                    String methodParameterSignature = m.toString().split("\\(")[1];
                    methodParameterSignature = methodParameterSignature.substring(0, methodParameterSignature.indexOf(')'));
                    String invokeExprParameterSignature = invokeExpr.toString().split("\\(")[1];
                    invokeExprParameterSignature = invokeExprParameterSignature.substring(0, invokeExprParameterSignature.indexOf(')'));

                    if (methodParameterSignature.equals(invokeExprParameterSignature)) {
                        return m;
                    }
                }
            }
            return defaultMethod;
        } catch (Throwable e) {
            LOGGER.debug("Could not find method via reflection {}", e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Finds matching constructor
     *
     * @param clazz      to look for constructors
     * @param invokeExpr to find matching constructors
     * @return constructor if any match
     */
    public static Constructor<?> findMatchingConstructor(Class<?> clazz, InvokeExpr invokeExpr) {
        try {
            Constructor<?>[] executables = clazz.getConstructors();
            Constructor<?> defaultConstructor = null;
            for (Constructor<?> m : executables) {
                if (m.getParameterCount() == 0) {
                    defaultConstructor = m;
                }
                if (invokeExpr.getArgCount() == m.getParameterCount()) {
                    if (m.toString().split("\\(")[1].replace(")", "")
                            .equals(invokeExpr.toString().split("\\(")[1].replace(")>", ""))) {
                        return m;
                    }
                }
            }
            return defaultConstructor;
        } catch (Throwable e) {
            LOGGER.debug("Could not find matching constructor {}", e.getLocalizedMessage());
            return null;
        }
    }

    /**
     * Creates default object for class if that is possible
     *
     * @param clazz to create object for
     * @return default object or null if it failed to create it
     */
    public static Object createDefaultObject(Class<?> clazz) {
        try {
            Constructor<?> constructor = clazz.getConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (Throwable e) {
            LOGGER.debug("Could not create default object");
        }
        try {
            for (Constructor<?> constructor : clazz.getConstructors()) {
                try {
                    constructor.setAccessible(true);
                    Class<?>[] params = constructor.getParameterTypes();
                    Object[] paramObjects = new Object[params.length];
                    for (int i = 0; i < params.length; i++) {
                        paramObjects[i] = getDefaultObject(params[i]);
                    }
                    return constructor.newInstance(paramObjects);
                } catch (Throwable e) {
                    LOGGER.debug(e.getLocalizedMessage());
                }
            }
        } catch (Throwable e) {
            LOGGER.debug("Could not create default object ");
        }
        return null;
    }

    /**
     * Tries to align arguments for later method calls
     *
     * @param args to align
     * @return List of aligned objects
     */
    public static List<List<Object>> alignArguments(List<Class<?>> classesOfArgs, HashSet<?>... args) {
        List<List<Object>> result = new ArrayList<>();
        List<List<Object>> arguments = new ArrayList<>();
        int max = 1;
        for (HashSet<?> arg : args) {
            if (arg != null && arg.size() > 0) {
                arguments.add(new ArrayList<>(arg));
                if (max < arg.size()) {
                    max = arg.size();
                }
            } else {
                arguments.add(new ArrayList<>());
            }
        }

        for (int i = 0; i < max; i++) {
            List<Object> current = new ArrayList<>();
            for (List<Object> arg : arguments) {
                if (arg.size() <= i) {
                    current.add(null);
                } else {
                    current.add(arg.get(i));
                }
            }
            for (int j = 0; j < current.size(); j++) {
                if (classesOfArgs.get(j).isArray() && current.get(j) != null) {
                    //Arrays are internally handled as lists, convert them back to arrays
                    if (current.get(j) instanceof List) {
                        try {
                            List<?> tmpCurrent = (List<?>) current.get(j);
                            current.set(j, Array.newInstance(classesOfArgs.get(j).getComponentType(), tmpCurrent.size()));
                            for (int ia = 0; ia < tmpCurrent.size(); ia++) {
                                ((Object []) current.get(j))[ia] = tmpCurrent.get(ia);
                            }
                        } catch (Exception e) {
                            current.set(j, null);
                        }
                    }
                } else if (current.get(j) != null) {
                    //cast to the right type to avoid exceptions while executing with reflection
                    try {
                        current.set(j, classesOfArgs.get(j).cast(current.get(j)));
                    } catch (ClassCastException e) {
                        current.set(j, null);
                    }
                }

                if (current.get(j) == null) {
                    current.set(j, getDefaultObject(classesOfArgs.get(j)));
                }
            }
            result.add(current);
        }
        return result;
    }

    /**
     * get default objects for class
     *
     * @param clazz to get default object from
     * @return the created object
     */
    public static Object getDefaultObject(Class<?> clazz) {
        if (clazz == null) {
            return null;
        } else if (clazz.isAssignableFrom(String.class)) {
            return "UNKNOWN";
        } else if (clazz.isAssignableFrom(Float.class)) {
            return 0.0f;
        } else if (clazz.isAssignableFrom(Integer.class)) {
            return 0;
        } else if (clazz.isAssignableFrom(Double.class)) {
            return 0.0d;
        } else if (clazz.isAssignableFrom(Boolean.class)) {
            return false;
        } else if (clazz.isAssignableFrom(Byte.class)) {
            return 0x00;
        } else if (clazz.isAssignableFrom(float.class)) {
            return 0.0f;
        } else if (clazz.isAssignableFrom(int.class)) {
            return 0;
        } else if (clazz.isAssignableFrom(double.class)) {
            return 0.0d;
        } else if (clazz.isAssignableFrom(boolean.class)) {
            return false;
        } else if (clazz.isAssignableFrom(byte.class)) {
            return 0x00;
        } else if (clazz.isAssignableFrom(char.class)) {
            return 'a';
        } else if (clazz.isAssignableFrom(float[].class)) {
            return new float[0];
        } else if (clazz.isAssignableFrom(int[].class)) {
            return new int[0];
        } else if (clazz.isAssignableFrom(double[].class)) {
            return new double[0];
        } else if (clazz.isAssignableFrom(boolean[].class)) {
            return new boolean[0];
        } else if (clazz.isAssignableFrom(byte[].class)) {
            return new byte[0];
        } else if (clazz.isAssignableFrom(char[].class)) {
            return new char[0];
        } else {
            try {
                if (clazz.isArray()) {
                    return Array.newInstance(clazz.getComponentType(), 0);
                } else {
                    return clazz.getConstructor().newInstance();
                }
            } catch (Throwable e) {
                LOGGER.debug("Could not create default object");
            }
        }
        return null;
    }


    public static Object getDefaultValue(SootField field, String clazzName) {
        try {
            Class<?> clazz = ReflectionHelper.getClass(clazzName);
            if (clazz != null) {
                return clazz.getField(field.getName()).get(null);
            }
        } catch (Throwable e) {
            LOGGER.debug("Could not get default object ... ");
        }
        return null;
    }

    public static Object getEnumObject(SootField field, String clazzName) {
        try {
            Class<?> clazz = ReflectionHelper.getClass(clazzName);
            if (clazz != null) {
                return Enum.valueOf((Class<? extends Enum>) clazz, field.getName());
            }
        } catch (Throwable e) {
            LOGGER.debug("Could not get Enum...");
        }
        return null;
    }

    public static List<Object> alignBaseObject(Set<Object> currentBaseObjects, int size, Class<?> clazz) { 
        List<Object> result = new ArrayList<>(currentBaseObjects);
        while (result.size() < size) {
            Object toAdd;
            if (result.size() > 0) {
                try {
                    Method cloneMethod = clazz.getMethod("clone");
                    cloneMethod.invoke(result.get(0));
                } catch (Throwable e) {
                    LOGGER.debug("Could not clone method try to create the default object");
                }
            }
            toAdd = ReflectionHelper.createDefaultObject(clazz); //create object default constructor
            if (toAdd == null) {
                return result;
            }
            result.add(toAdd);
        }
        return result;

    }
}
