import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.AccessFlag;

import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Modifier;
import java.util.*;

public class InstrumentationHelper {

    /**
     * @param aClass to check for own to string method
     * @return true if class has to string method
     */
    public static boolean classImplementsToString(final CtClass aClass) {
        try {
            aClass.getDeclaredMethod("toString");
            return true;
        } catch (NotFoundException e) {
            try {
                if ((aClass.getMethod("toString", "()Ljava/lang/String;").getModifiers() & AccessFlag.FINAL) == 0) {
                    return false;
                }
            } catch (NotFoundException e2) {
                //We cannot do much here, if that happens we better don't change the existing implementation
            }

            return true;

        }
    }

    /**
     * @param aClass to check for own to string method
     * @return true if class has to string method
     */
    public static boolean classImplementsToString(Class<?> aClass) {
        try {
            aClass.getDeclaredMethod("toString");
            return true;
        } catch (NoSuchMethodException e) {
            return false;

        }
    }

    /**
     * @param aClass to check for own to string method
     * @return true if class has to string method
     */
    public static boolean classImplementsHashCode(Class<?> aClass) {
        try {
            aClass.getDeclaredMethod("hashCode");
            return true;
        } catch (NoSuchMethodException e) {
            return false;

        }
    }

    /**
     * @param aClass to check for own to string method
     * @return true if class has to string method
     */
    public static boolean classImplementsEquals(Class<?> aClass) {
        try {
            aClass.getDeclaredMethod("equals", Object.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;

        }
    }

    /**
     * @param aClass to check for own hashCode method
     * @return true if class has hashCode method
     */
    public static boolean classImplementsHashCode(final CtClass aClass) {
        try {
            aClass.getDeclaredMethod("hashCode");
            return true;
        } catch (NotFoundException e) {
            try {
                if ((aClass.getMethod("hashCode", "()I").getModifiers() & AccessFlag.FINAL) == 0) {
                    return false;
                }
            } catch (NotFoundException e2) {
                //We cannot do much here, if that happens we better don't change the existing implementation
            }
            return true;

        }
    }

    /**
     * @param aClass to check for own equals method
     * @return true if class has equals method
     */
    public static boolean classImplementsEquals(final CtClass aClass) {
        try {
            aClass.getDeclaredMethod("equals");
            return true;
        } catch (NotFoundException e) {
            try {
                if ((aClass.getMethod("equals", "(Ljava/lang/Object;)Z").getModifiers() & AccessFlag.FINAL) == 0) {
                    return false;
                }
            } catch (NotFoundException e2) {
                //We cannot do much here, if that happens we better don't change the existing implementation
            }
            return true;

        }
    }

    /**
     * Implementation for equal method
     *
     * @param obj1 base object
     * @param obj2 other object
     * @return true if objects equal
     */
    public static boolean getObjectsEqual(Object obj1, Object obj2, int callDepth) {
        if (obj1 == obj2) return true;
        if (obj2 == null || obj1.getClass() != obj2.getClass()) return false;

        try {
            Object object2Casted = obj1.getClass().cast(obj2);

            List<Field> allFields = getAllFields(obj1.getClass());
            Object[] fieldObjects1 = new Object[allFields.size()];
            Object[] fieldObjects2 = new Object[allFields.size()];

            for (int i = 0; i < allFields.size(); i++) {
                try {
                    Field field = allFields.get(i);

                    if ((field.getModifiers() & Modifier.TRANSIENT) != 0 || (field.getModifiers() & Modifier.STATIC) != 0) {
                        continue;
                    }

                    field.setAccessible(true);
                    fieldObjects1[i] = field.get(obj1);
                    fieldObjects2[i] = field.get(object2Casted);
                } catch (IllegalAccessException| InaccessibleObjectException e) {
                    //We cannot fix the issue continue with the next field, however should not happen since we set accessible to true
                }
            }
            for (int i = 0; i < fieldObjects1.length; i++) {
                if (fieldObjects1[i] == null && fieldObjects2[i] == null) {
                    continue;
                }

                if (fieldObjects1[i] == null || fieldObjects2[i] == null) {
                    return false;
                }

                if (useExistingEquals(fieldObjects1[i]) && useExistingEquals(fieldObjects2[i])) {
                    if (!fieldObjects1[i].equals(fieldObjects2[i])) {
                        return false;
                    }
                } else {
                    if (callDepth < 10) {
                        if (!getObjectsEqual(fieldObjects1[i], fieldObjects2[i], callDepth + 1)) {
                            return false;
                        }
                    }
                }
            }

            return true;
        } catch (ClassCastException e2) {
            //just in case -> but should not be possible to happen
            return false;
        }
    }

    /**
     * HashCode method that get injected into other classes
     *
     * @param obj base object to get the hashCode from
     * @return hashCode of object
     */
    public static int getHashCode(Object obj, int callDepth) {
        List<Field> allFields = getAllFields(obj.getClass());
        List<Object> objects = new ArrayList<>();

        for (int i = 0; i < allFields.size(); i++) {
            Field field = allFields.get(i);
            if ((field.getModifiers() & Modifier.TRANSIENT) != 0 || (field.getModifiers() & Modifier.STATIC) != 0) {
                continue;
            }
            try {
                Object fieldObject = field.get(obj);
                if (fieldObject == null) {
                    objects.add(0);
                    continue;
                }
                objects.add(fieldObject);
            } catch (IllegalArgumentException | IllegalAccessException| InaccessibleObjectException e) {
            }
        }
        int result = 0;
        for (Object o : objects) {
            if (useExistingHashCode(obj)) {
                result = 31 * result + o.hashCode();
            } else {
                if (callDepth < 10) {
                    result = 31 * result + getHashCode(o, callDepth + 1);
                }
            }
        }
        return result;
    }

    /**
     * @param clazz to get field
     * @return all fields from class
     */
    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> allFields = new ArrayList<>();
        Class<?> currentClazz = clazz;
        Set<Class<?>> allClasses = new HashSet<>();
        allFields.addAll(Arrays.asList(currentClazz.getDeclaredFields()));

        return allFields;
    }


    private static boolean useImplementedMethod(Object obj) {
        Class<?> currentClazz = obj.getClass();
        return currentClazz.isPrimitive() || (currentClazz.getName().startsWith("java.") && !obj.getClass().getName().startsWith("java.util")) || currentClazz.getName().startsWith("sun.") || currentClazz.getName().startsWith("javax.") || currentClazz.getName().startsWith("android.")
                || currentClazz.getName().startsWith("kotlinx.") || currentClazz.getName().startsWith("kotlin.") ||
                currentClazz.getName().startsWith("androidx.") || currentClazz.getName().startsWith("com.sun.")
                || currentClazz.getName().startsWith("jdk.") || currentClazz.getName().startsWith("heros.") || currentClazz.getName().startsWith("org.jf.dexlib2.")
                || currentClazz.getName().startsWith("pxb.android.") || currentClazz.getName().startsWith("com.intellij.") || currentClazz.getName().startsWith("iotscope.");
    }

    private static boolean useExistingToString(Object obj) {
        return useImplementedMethod(obj) && classImplementsToString(obj.getClass());
    }

    private static boolean useExistingEquals(Object obj) {
        return useImplementedMethod(obj) && classImplementsEquals(obj.getClass());
    }

    private static boolean useExistingHashCode(Object obj) {
        return useImplementedMethod(obj) && classImplementsHashCode(obj.getClass());
    }

    /**
     * toString method that get injected into other classes
     *
     * @param obj base object to get the toString from
     * @return String of object
     */
    public static String getToString(Object obj, int callDepth) {
        List<Field> allFields = getAllFields(obj.getClass());
        String fieldString = "";
        for (Field field : allFields) {
            try {
                if ((field.getModifiers() & Modifier.TRANSIENT) != 0 || (field.getModifiers() & Modifier.STATIC) != 0) {
                    continue;
                }
                field.setAccessible(true);
                Object currentValue = field.get(obj);
                if (currentValue != null) {
                    if (callDepth < 10) {

                        if (currentValue.getClass().isArray()) {
                            String s = currentValue.toString();
                            if (s.contains("@")) {
                                fieldString = fieldString + Arrays.toString((Object[]) currentValue) + ",";
                            }else {
                                fieldString = fieldString + s;
                            }
                        } else if (currentValue instanceof List) {
                            List<?> objList = (List<?>) currentValue;
                            String s = objList.toString();
                            if (s.contains("@")) {
                                fieldString = fieldString + Arrays.toString(objList.toArray()) + ",";
                            }else {
                                fieldString = fieldString + s;
                            }
                        } else if (currentValue instanceof Set) {
                            List<?> objList = new ArrayList<>((Set<?>) currentValue);
                            String s = objList.toString();
                            if (s.contains("@")) {
                                fieldString = fieldString + Arrays.toString(objList.toArray()) + ",";
                            }else {
                                fieldString = fieldString + s;
                            }
                        } else if (currentValue instanceof Enumeration) {
                            fieldString += "[";
                            while (((Enumeration<?>) currentValue).hasMoreElements()) {
                                fieldString += ((Enumeration<?>) obj).nextElement();
                                fieldString += ((Enumeration<?>) obj).hasMoreElements() ? ", " : "";
                            }
                            fieldString += "]";
                        } else if (useExistingToString(currentValue)) {
                            fieldString = fieldString + currentValue.toString() + ",";
                        } else {
                            fieldString = fieldString + getToString(currentValue, callDepth + 1) + ",";

                        }
                    }
                }
            } catch (IllegalAccessException| InaccessibleObjectException | ClassCastException e) {
                //We cannot fix the issue continue with the next field, however should not happen since we set accessible to true
            }
        }
        if (fieldString.length() > 0 && fieldString.charAt(fieldString.length() - 1) == ',') {
            fieldString = fieldString.substring(0, fieldString.length() - 1);
        }
        return obj.getClass().getName() + "(" + fieldString + ")";
    }
}
