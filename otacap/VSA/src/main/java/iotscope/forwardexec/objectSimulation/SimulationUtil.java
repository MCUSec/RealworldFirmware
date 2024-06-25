package iotscope.forwardexec.objectSimulation;

import com.google.gson.*;
import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientBuilder;
import com.hivemq.client.mqtt.datatypes.MqttTopic;
import com.hivemq.client.mqtt.datatypes.MqttTopicBuilder;
import com.hivemq.client.mqtt.datatypes.MqttTopicFilter;
import com.hivemq.client.mqtt.datatypes.MqttTopicFilterBuilder;
import iotscope.utility.LoopjHeader;
import iotscope.utility.ReflectionHelper;
import okhttp3.*;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.IntegerType;
import soot.Value;
import soot.jimple.*;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;


public class SimulationUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimulationUtil.class);
    private static final String IP_DOMAIN_MATCHER = "([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z0-9]{2,}";
    private static final Pattern IP_DOMAIN_PATTERN = Pattern.compile(IP_DOMAIN_MATCHER);

    public static Value getKeyValue(Value value) {
        Value result = value;

        if (result instanceof ArrayRef) {
            result = ((ArrayRef) result).getBase();
        }
        return result;
    }


    private static HashSet<?> getArrayRefValues(ArrayRef ref, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Object> result = new HashSet<>();

        Value base = ref.getBase();
        HashSet<ArrayList<?>> tmpArray;
        if (!currentValues.containsKey(base)) {
            return result;
        } else {
            tmpArray = (HashSet<ArrayList<?>>) currentValues.get(base);
        }
        Iterator<ArrayList<?>> iterator = tmpArray.iterator();
        if (tmpArray == null || !iterator.hasNext()) {
            return result;
        }

        int min = SimulationUtil.getMinIndexOfArray(ref, currentValues);
        while (iterator.hasNext()) {
            try {
                List<?> current =  (List<?>)  iterator.next();
                if (current == null) {
                    continue;
                }
                if (min >= 0 && min < current.size()) {
                    result.add(current.get(min));
                } else if (min >= 0 && min >= current.size() && current.size() > 0) {
                    result.add(current.get(current.size() - 1));
                } else if (min < 0 && current.size() > 0) {
                    for (Object e : current) {
                        HashSet<Object> currentSet = new HashSet<>();
                        currentSet.add(e);
                        result.add(currentSet);
                    }
                }
            } catch (ClassCastException e) {
                LOGGER.error(e.getLocalizedMessage());
                return new HashSet<>();
            }
        }
        return result;

    }


    public static <T> HashSet<T> getObjects(Value value, HashMap<Value, HashSet<?>> currentValues, Class<T> clazz, T defaultObject) {
        HashSet<T> vs = new HashSet<>();
        HashSet<?> requests = getCurrentValues(value, currentValues);
        if (requests == null || requests.size() == 0) {
            vs.add(defaultObject);
            currentValues.put(value, vs);
            return vs;
        }
        requests.forEach(co -> {
            if (co != null) {
                try {
                    vs.add(co.getClass().isInstance(clazz) || co.getClass().equals(clazz) ? clazz.cast(co) : defaultObject);
                } catch (ClassCastException e) {
                    LOGGER.debug("could not cast {} to {}", co, clazz);
                    if (clazz.equals(String.class)) {
                        try {
                            vs.add((clazz).cast(co.toString()));
                        } catch (ClassCastException e2) {
                            vs.add(defaultObject);
                        }
                    } else {
                        vs.add(defaultObject);

                    }
                }
            } else {
                vs.add(defaultObject);
            }
        });

        if (vs.size() == 0) {
            LOGGER.debug("There is no value for {} available", value);
            vs.add(defaultObject);
        }
        currentValues.put(value, vs);
        return vs;
    }


    public static HashSet<?> getCurrentValues(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof ArrayRef) {
            return getArrayRefValues((ArrayRef) value, currentValues);
        } else if (value instanceof CastExpr) {
            value = ((CastExpr) value).getOp();
        } else if (value instanceof Constant) {
            return getConstant(value);
        }
        return currentValues.get(value);
    }

    public static HashSet<?> getConstant(Value value) {
        if (value instanceof StringConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((StringConstant) value).value);
            return result;
        } else if (value instanceof FloatConstant) {
            HashSet<Float> result = new HashSet<>();
            result.add(((FloatConstant) value).value);
            return result;
        } else if (value instanceof IntConstant) {
            HashSet<Integer> result = new HashSet<>();
            result.add(((IntConstant) value).value);
            return result;
        } else if (value instanceof DoubleConstant) {
            HashSet<Double> result = new HashSet<>();
            result.add(((DoubleConstant) value).value);
            return result;
        } else if (value instanceof LongConstant) {
            HashSet<Long> result = new HashSet<>();
            result.add(((LongConstant) value).value);
            return result;
        } else if (value instanceof NullConstant) {
            //Nothing to do here
        } else if (value instanceof ClassConstant) {
            HashSet<Class<?>> result = new HashSet<>();
            String className = ((ClassConstant) value).getValue();
            if (className.length()>1) {
                int indexSemicolon = className.indexOf(";");
                if (indexSemicolon>1) {
                    className = className.substring(1, indexSemicolon);
                }
                className = className.replace("/", ".");
            }
            result.add(ReflectionHelper.getClass(className));
            return result;
        }
        return new HashSet<>();
    }


    public static HashSet<Object> getObjectOrConstant(Value value, HashMap<Value, HashSet<?>> currentValues) {
        
        HashSet<?> result = getCurrentValues(value, currentValues);
        if (result == null || result.size() == 0) {
            result = new HashSet<>();
        }
        return (HashSet<Object>) result;
    }


    public static HashSet<Boolean> getBoolean(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Boolean.class, Boolean.FALSE);
    }

    public static HashSet<List> getList(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, List.class, new ArrayList());
    }

    public static HashSet<Set> getSet(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Set.class, new HashSet());
    }

    public static HashSet<Map> getMap(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Map.class, new HashMap());
    }

    public static HashSet<Map> getLoopjRequestParamMap(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Map.class, new HashMap<String, Object>());
    }

    public static HashSet<Collection> getCollection(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Collection.class, new ArrayList());
    }

    public static HashSet<FormBody.Builder> getFormBodyBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, FormBody.Builder.class, new FormBody.Builder());
    }

    public static HashSet<HttpUrl.Builder> getHttpUrlBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, HttpUrl.Builder.class, new HttpUrl.Builder());
    }

    public static HashSet<Request> getOkHttpRequest(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Request.class, new Request.Builder().url("https://not_found.com").build());
    }

    public static HashSet<File> getFile(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, File.class, new File(""));
    }

    public static HashSet<File[]> getFileArray(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, File[].class, new File[0]);
    }

    public static HashSet<MediaType> getOkhttp3MediaType(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MediaType.class, MediaType.get("UNKNOWN"));
    }

    public static HashSet<Headers.Builder> getOkhttp3HeadersBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Headers.Builder.class, new Headers.Builder());
    }

    public static HashSet<Headers> getOkhttp3Headers(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Headers.class, new Headers.Builder().build());
    }



    public static HashSet<HttpUrl> getHttpUrl(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, HttpUrl.class, new HttpUrl.Builder().scheme("http").host("not_found.at").build());
    }

    public static HashSet<URL> getJavaNetURL(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, URL.class, null);
    }

    public static HashSet<InetAddress> getInetAddress(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, InetAddress.class, null);

    }

    public static HashSet<InetSocketAddress> getInetSocketAddress(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, InetSocketAddress.class, null);
    }


    public static HashSet<URI> getJavaNetURI(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, URI.class, null);
    }


    public static HashSet<Properties> getJavaProperties(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Properties.class, null);
    }

    public static HashSet<JSONObject> getJSONObjects(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, JSONObject.class, new JSONObject());
    }

    public static HashSet<JSONArray> getJSONArrays(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, JSONArray.class, new JSONArray());
    }


    public static HashSet<String> getStringContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof StringConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((StringConstant) value).value);
            return result;
        } else if (value instanceof IntConstant) {
            HashSet<String> result = new HashSet<>();
            result.add((((IntConstant) value).value) + "");
            return result;
        }         
        else {
            return getObjects(value, currentValues, String.class, "");
        }
    }

    public static HashSet<Gson> getGsonContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Gson.class, new Gson());
    }


    public static HashSet<JsonArray> getJsonArrayContent(Value value, HashMap<Value, HashSet<?>> currentValues) {

        return getObjects(value, currentValues, JsonArray.class, new JsonArray());

    }


    public static HashSet<JsonObject> getJsonObjectContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, JsonObject.class, new JsonObject());

    }

    public static HashSet<JsonElement> getJsonElementContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, JsonElement.class, new JsonNull());

    }

    public static HashSet<Integer> getIntContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof IntConstant) {
            HashSet<Integer> result = new HashSet<>();
            result.add(((IntConstant) value).value);
            return result;
        } else {
            return getObjects(value, currentValues, Integer.class, 0);
        }
    }


    public static HashSet<Float> getFloatContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof FloatConstant) {
            HashSet<Float> result = new HashSet<>();
            result.add(((FloatConstant) value).value);
            return result;
        } else {
            return getObjects(value, currentValues, Float.class, 0f);
        }
    }

    public static HashSet<Double> getDoubleContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof DoubleConstant) {
            HashSet<Double> result = new HashSet<>();
            result.add(((DoubleConstant) value).value);
            return result;
        } else {
            return getObjects(value, currentValues, Double.class, 0d);
        }
    }


    public static HashSet<Character> getCharContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof IntConstant) {
            HashSet<Character> result = new HashSet<>();
            result.add((char) ((IntConstant) value).value);
            return result;
        } else {
            return getObjects(value, currentValues, Character.class, 'a');
        }
    }

    public static HashSet<Long> getLongContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof LongConstant) {
            HashSet<Long> result = new HashSet<>();
            result.add(((LongConstant) value).value);
            return result;
        } else {
            return getObjects(value, currentValues, Long.class, 0L);
        }
    }

    public static HashSet<Byte> getByteContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, Byte.class, (byte) 0);
    }


    public static HashSet<MqttMessage> getMqttMessage(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttMessage.class, new MqttMessage());
    }


    public static HashSet<MqttClientBuilder> getHivemqClientBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttClientBuilder.class, MqttClient.builder());
    }

    public static HashSet<MqttTopicBuilder> getHivemqTopicBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttTopicBuilder.class, MqttTopic.builder());
    }


    public static HashSet<MqttClient> getHivemqTopic(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttClient.class, null);
    }


    public static HashSet<CoapClient.Builder> getCoapClientBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, CoapClient.Builder.class, null);
    }

    public static HashSet<MqttTopicFilterBuilder> getHivemqTopicFilterBuilder(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttTopicFilterBuilder.class, MqttTopicFilter.builder());
    }

    public static HashSet<MqttTopicFilter> getHivemqTopicFilter(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, MqttTopicFilter.class, null);
    }

    public static HashSet<byte[]> getByteArrayContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, byte[].class, new byte[0]);
    }

    public static HashSet<LoopjHeader> getLoopjHeaderContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, LoopjHeader.class, new LoopjHeader("", ""));
    }

    public static HashSet<LoopjHeader[]> getLoopjHeaderArrayContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, LoopjHeader[].class, new LoopjHeader[0]);
    }

    public static HashSet<List<String>> getStringArrayContent(Value value, HashMap<Value, HashSet<?>> currentValues) {
        return getObjects(value, currentValues, getObjectType(), new ArrayList<>());
    }


    public static HashSet<String> getStringContentFromDouble(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof DoubleConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((DoubleConstant) value).value + "");
            return result;
        } else {
            //return getObjects(value, currentValues, Double.class, 0d);
            return getObjects(value, currentValues, String.class, "");
            //System.out.println("Error: something bad happened at SimulationUtil.getStringContentFromDouble. " + value);
            //return null;
        }
    }

    public static HashSet<String> getStringContentFromBoolean(Value value, HashMap<Value, HashSet<?>> currentValues) {
        
            HashSet<String> result = new HashSet<>();
            String strValue = "[default.Boolean]";

            if (value instanceof IntConstant) {
                IntConstant intValue = (IntConstant) value;
                if (intValue.value == 1) {
                    strValue = "true";
                } else if (intValue.value == 0){
                    strValue = "false";
                } else {
                    System.out.println("Error: Bad boolean value at SimulationUtil.getStringContentFromBoolean. " + value);
                }
            } else {
                System.out.println("Error: something bad happened at SimulationUtil.getStringContentFromBoolean. " + value);
            }

            result.add(strValue);
            return result;
        
            //return getObjects(value, currentValues, Double.class, 0d);
            
        
    }

    public static HashSet<String> getStringContentFromInt(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof IntConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((IntConstant) value).value + "");
            return result;
        } else if(value.getType() instanceof IntegerType) {
            HashSet<String> result = new HashSet<>();
            HashSet<Integer> intValues = getObjects(value, currentValues, Integer.class, 0);
            for (Integer intValue : intValues) {
                result.add(String.valueOf(intValue));
            }
            return result;
        }
        else {
            return getObjects(value, currentValues, String.class, "");
        }
    }

    public static HashSet<String> getStringContentFromFloat(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof FloatConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((FloatConstant) value).value + "");
            return result;
        } else {
            return getObjects(value, currentValues, String.class, "");
        }
    }

    public static HashSet<String> getStringContentFromLong(Value value, HashMap<Value, HashSet<?>> currentValues) {
        if (value instanceof LongConstant) {
            HashSet<String> result = new HashSet<>();
            result.add(((LongConstant) value).value + "");
            return result;
        } else {
            return getObjects(value, currentValues, String.class, "");
        }
    }

    public static Class<List<String>> getObjectType() {
        return (Class<List<String>>) ((Class) List.class);
    }

    public static int getMinIndexOfArray(ArrayRef ref, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Integer> index = SimulationUtil.getIntContent(ref.getIndex(), currentValues);
        OptionalInt minIndex = index.stream().mapToInt(x -> x).min();
        int min;

        if (minIndex.isPresent()) {
            min = minIndex.getAsInt();
            //NOTE: at the moment it is expected that there are not multiple versions of the array
        } else {
            min = -1;
            LOGGER.debug("Could not find the index of {} will assume index is 0", ref);
        }
        if (min < 0) {
            return -1;
        }
        return min;
    }


    public static boolean validProtocol(String url) {
        return url.startsWith("http") || url.startsWith("https") || url.startsWith("ftp") || url.startsWith("file") || url.startsWith("jar") || url.startsWith("unknown");
    }

    public static String addProtocolToString(String base) {
        String result;
        if (base.startsWith("://")) {
            result = "unknown" + base;
        } else if (base.startsWith(":")) {
            result = "unknown://" + base.replaceFirst(":", "");
        } else if (base.startsWith("/")) {
            result = "unknown://" + base.replaceFirst("/", "");
        } else {
            result = "unknown://" + base;
        }
        return result;
    }

    /**
     * sanitize a URL string if everything else failed
     *
     * @param url to sanitize
     * @return sanitized string
     */
    public static String sanitizeURL(String url) {
        url = url.replace("[", "").replace("]", "");
        url = url.replace("%d/", "1111/");
        url = url.replace("%d", "1111/");

        String protocol = "";

        int indexOfProtocol = url.indexOf(":/");
        if (indexOfProtocol > 2) {
            protocol = url.substring(0, url.indexOf(":/"));
            protocol += "://";
        }
        try {
            String domain = IP_DOMAIN_PATTERN.matcher(url).group(0);
            return protocol + domain;
        } catch (IllegalStateException e) {
            LOGGER.error(e.getLocalizedMessage());
            return url;
        }
    }

    public static String findDomain(String url) {
        try {
            return IP_DOMAIN_PATTERN.matcher(url).group(0);
        } catch (IllegalStateException e) {
            LOGGER.error(e.getLocalizedMessage());
            return url;
        }
    }


    public static <T> HashSet<List<T>> initArray(T initObject, NewArrayExpr newArrayExpr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Integer> size = getIntContent(newArrayExpr.getSize(), currentValues);
        OptionalInt max = size.stream().mapToInt(x -> x).max();
        HashSet<List<T>> initValue = new HashSet<>();
        if (max.isPresent()) {
            int maxToSimulate = Math.min( 10000, max.getAsInt());
            List<T> array = new ArrayList<>();
            for (int i = 0; i < maxToSimulate; i++) {
                //array.add(i, "" + i);
                array.add(i, initObject);
            }
            initValue.add(array);
        }
        return initValue;
    }


    public static List<String> getSimulatedArrayOrInit(Value base, int index, Value value, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<List<String>> tmpArray = new HashSet<>();

        if (!currentValues.containsKey(base)) {
            tmpArray.add(new ArrayList<>(Arrays.asList(new String[index + 1])));
        } else {
            HashSet<Object> values = (HashSet<Object>) currentValues.get(base);

            for (Object current : values) {
                List<String> tempArray = new ArrayList<>();
                if (current instanceof List) {
                    for (Object o : (List<Object>) current) {
                        if (o != null && !o.toString().startsWith("java.lang.Object@")) {
                            tempArray.add(o.toString());
                        } else {
                            tempArray.add("");
                        }

                    }
                } else {
                    if (current == null) {
                        tempArray.add("");
                    } else {
                        tempArray.add(current.toString());
                    }
                }
                tmpArray.add(tempArray);
            }
        }
        if (tmpArray.iterator().hasNext()) {
            return tmpArray.iterator().next();
        } else {
            return new ArrayList<>();
        }
    }


}
