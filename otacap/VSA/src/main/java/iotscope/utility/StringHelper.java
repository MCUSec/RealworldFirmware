package iotscope.utility;

import com.google.gson.Gson;
import okhttp3.FormBody;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.util.*;

public class StringHelper {

    public static String objectToString(Object obj) {
        try {
            if (obj instanceof FormBody) {
                try {
                    Buffer buffer = new Buffer();
                    ((FormBody) obj).writeTo(buffer);

                    return buffer.readUtf8();
                } catch (Exception e) {
                    return "";
                }
            } else if (obj instanceof List) {
                List<?> objList = (List<?>) obj;
                String result = Arrays.toString(objList.toArray());
                if (!result.contains("@")) {
                    return result;
                }
                result = "[";
                for (int i = 0; i < objList.size(); i++) {
                    result += objectToString(objList.get(i)) + (i < objList.size() - 1 ? ", " : "");
                }
                return result + "]";
            } else if (obj instanceof Set) {
                List<?> objList = new ArrayList<>((Set<?>) obj);
                String result = Arrays.toString(objList.toArray());
                if (!result.contains("@")) {
                    return result;
                }
                result = "[";
                for (int i = 0; i < objList.size(); i++) {
                    result += objectToString(objList.get(i)) + (i < objList.size() - 1 ? ", " : "");
                }
                return result + "]";
            } else if (obj instanceof Map) {
                Map<?, ?> objMap = (Map<?, ?>) obj;
                String result = "{";
                Object[] keys = objMap.keySet().toArray();

                for (int i = 0; i < keys.length; i++) {
                    result += objectToString(keys[i]) + ": " + objectToString(objMap.get(keys[i]));
                    result += i < keys.length - 1 ? ", " : "";
                }
                return result + "}";
            } else if (obj instanceof Enumeration) {
                String result = "[";
                while (((Enumeration<?>) obj).hasMoreElements()) {
                    result += objectToString(((Enumeration<?>) obj).nextElement());
                    result += ((Enumeration<?>) obj).hasMoreElements() ? ", " : "";
                }
                return result + "]";
            } else if (obj instanceof MultipartBody) {
                return Arrays.toString(((MultipartBody) obj).parts().toArray());
            } else if (obj instanceof DatagramPacket) {
                DatagramPacket tmp = (DatagramPacket) obj;
                return tmp.getAddress().toString() + ";" + tmp.getPort() + ";" + Arrays.toString(tmp.getData()) + ";" + tmp.getSocketAddress();
            } else if (obj != null && obj.getClass().isArray()) {
                if (obj.getClass().equals(byte[].class)) {
                    return Arrays.toString((byte[]) obj);
                } else if (obj.getClass().equals(int[].class)) {
                    return Arrays.toString((int[]) obj);
                } else if (obj.getClass().equals(char[].class)) {
                    return Arrays.toString((char[]) obj);
                } else if (obj.getClass().equals(float[].class)) {
                    return Arrays.toString((float[]) obj);
                } else if (obj.getClass().equals(long[].class)) {
                    return Arrays.toString((long[]) obj);
                } else if (obj.getClass().equals(short[].class)) {
                    return Arrays.toString((short[]) obj);
                } else if (obj.getClass().equals(double[].class)) {
                    return Arrays.toString((double[]) obj);
                } else if (obj.getClass().equals(boolean[].class)) {
                    return Arrays.toString((boolean[]) obj);
                } else {
                    Object[] objList = (Object[]) obj;
                    String result = "[";
                    for (int i = 0; i < objList.length; i++) {
                        result += objectToString(objList[i]) + (i < objList.length - 1 ? ", " : "");
                    }
                    return result + "]";
                }
            } else if (obj instanceof InputStream) {
                try {
                    return "InputStream@Object";
                } catch (Exception e) {
                    return "";
                }
            } else if (obj instanceof RequestBody) {
                RequestBody request = (RequestBody) obj;

                try {
                    final Buffer buffer = new Buffer();
                    request.writeTo(buffer);
                    return buffer.readUtf8();
                } catch (IOException e) {
                }
                return "";

            } else if (obj instanceof Gson) {
                return "gson@object";
            } else {
                String returnString = obj == null ? "" : obj.toString();
                if (obj != null && obj.getClass().getName().contains("proto") && returnString.equals("")) {
                    return obj.getClass().getName() + "@proto";
                }
                if (returnString.contains("@") && !objectHasToStringImplemented(obj)) {
                    if (obj.getClass().getName().contains("Builder")) {
                        try {
                            returnString = obj.getClass().getMethod("build").invoke(obj).toString();
                        } catch (Throwable e) {

                        }
                    }
                    if (returnString.contains("@")) {
                        returnString = obj.getClass().getName() + "@Object";
                    }
                }

                return returnString;
            }
        } catch (Throwable e) {
            return obj != null ? obj.getClass().getName() : "";
        }
    }


    public static HashSet<String> getStringRepresentations(Set<Object> currentResult) {
        HashSet<String> result = new HashSet<>();
        currentResult.forEach(x -> result.add(objectToString(x)));
        return result;
    }


    private static boolean objectHasToStringImplemented(final Object o) {
        return classHasToStringImplemented(o.getClass());
    }


    private static boolean classHasToStringImplemented(final Class<?> initialClass) {

        Class<?> classToCheck = initialClass;
        while (classToCheck != Object.class) {
            if (classImplementsToString(classToCheck)) {
                return true;
            }

            classToCheck = classToCheck.getSuperclass();
        }

        return false;
    }


    private static boolean classImplementsToString(final Class<?> aClass) {
        try {
            aClass.getDeclaredMethod("toString");
            return true;

        } catch (NoSuchMethodException e) {
            return false;

        }
    }
}
