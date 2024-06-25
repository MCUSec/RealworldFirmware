package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.io.File;
import java.net.URL;
import java.util.*;

public class OkHttpSimulation implements SimulationObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(OkHttpSimulation.class);


    public OkHttpSimulation() {
    }

    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        if (rightValue.getType().toString().equals("okhttp3.HttpUrl$Builder")) {
            return initBuilder();
        }
        return null;
    }


    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("okhttp3")) {
            HashSet<HttpUrl> urls = new HashSet<>();
            switch (signature) {
                case "<okhttp3.HttpUrl: okhttp3.HttpUrl parse(java.lang.String)>":
                    HashSet<String> values = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    values.forEach(u -> {
                        if (u != null) {
                            urls.add(HttpUrl.parse(u));
                        }
                    });
                    break;
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder scheme(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return scheme(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder host(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    return host(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder addPathSegment(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return addPathSegment(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl build()>":
                    return build(((VirtualInvokeExpr) expr).getBase(), currentValues);
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder encodedUsername(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return encodedUsername(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder addQueryParameter(java.lang.String,java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> param0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> param1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);


                    return addQueryParameter(from, param0, param1, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder addEncodedPathSegment(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return addEncodedPathSegment(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder addEncodedPathSegments(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return addEncodedPathSegments(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder addEncodedQueryParameter(java.lang.String,java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> param0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> param1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);


                    return addEncodedQueryParameter(from, param0, param1, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder encodedFragment(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return encodedFragment(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder encodedPassword(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return encodedPassword(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder encodedPath(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return encodedPath(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder encodedQuery(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return encodedQuery(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder password(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    return password(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder fragment(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);

                    return fragment(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder port(int)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<Integer> schemeValues = SimulationUtil.getIntContent(expr.getArg(0), currentValues);

                    return port(from, schemeValues, currentValues);

                }
                case "<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl$Builder query(java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> schemeValues = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    return query(from, schemeValues, currentValues);
                }
                case "<okhttp3.HttpUrl$Builder: java.lang.String toString()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    return toString(from, currentValues);
                }
                case "<okhttp3.HttpUrl: java.net.URL url()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    return toURL(from, currentValues);
                }
                case "<okhttp3.Request: okhttp3.HttpUrl url()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    return url(from, currentValues);
                }
                case "<okhttp3.FormBody$Builder: okhttp3.FormBody build()>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    return formBodyBuilder(from, currentValues);
                }
                case "<okhttp3.FormBody$Builder: okhttp3.FormBody$Builder addEncoded()>":
                case "<okhttp3.FormBody$Builder: okhttp3.FormBody$Builder add(java.lang.String,java.lang.String)>": {
                    Value from = ((VirtualInvokeExpr) expr).getBase();
                    HashSet<String> param0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> param1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    return addFormBodyValue(from, param0, param1, currentValues);
                }
                case "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,byte[])>":
                case "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,byte[],int,int)>": {
                    HashSet<MediaType> arg0 = SimulationUtil.getOkhttp3MediaType(expr.getArg(0), currentValues);
                    HashSet<byte[]> arg1 = SimulationUtil.getByteArrayContent(expr.getArg(1), currentValues);
                    HashSet<RequestBody> requestBodies = new HashSet<>();
                    Iterator<MediaType> arg0Iterator = arg0.iterator();
                    Iterator<byte[]> arg1Iterator = arg1.iterator();
                    while (arg0Iterator.hasNext() && arg1Iterator.hasNext()) {
                        try {
                            requestBodies.add(RequestBody.create(arg0Iterator.next(), arg1Iterator.next()));
                        } catch (Exception e) {
                            LOGGER.error("Could not create request body");
                        }
                    }
                    return requestBodies;
                }
                case "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,java.io.File)>": {
                    HashSet<MediaType> arg0 = SimulationUtil.getOkhttp3MediaType(expr.getArg(0), currentValues);
                    HashSet<File> arg1 = SimulationUtil.getFile(expr.getArg(1), currentValues);
                    HashSet<RequestBody> requestBodies = new HashSet<>();
                    Iterator<MediaType> arg0Iterator = arg0.iterator();
                    Iterator<File> arg1Iterator = arg1.iterator();
                    while (arg0Iterator.hasNext() && arg1Iterator.hasNext()) {
                        try {
                            requestBodies.add(RequestBody.create(arg0Iterator.next(), arg1Iterator.next()));
                        } catch (Exception e) {
                            LOGGER.error("Could not create request body");
                        }
                    }
                    return requestBodies;
                }
                case "<okhttp3.RequestBody: okhttp3.RequestBody create(okhttp3.MediaType,java.lang.String)>": {
                    HashSet<MediaType> arg0 = SimulationUtil.getOkhttp3MediaType(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<RequestBody> requestBodies = new HashSet<>();
                    Iterator<MediaType> arg0Iterator = arg0.iterator();
                    Iterator<String> arg1Iterator = arg1.iterator();
                    while (arg0Iterator.hasNext() && arg1Iterator.hasNext()) {
                        try {
                            requestBodies.add(RequestBody.create(arg0Iterator.next(), arg1Iterator.next()));
                        } catch (Exception e) {
                            LOGGER.error("Could not create request body");
                        }
                    }
                    return requestBodies;
                }
                case "<okhttp3.MediaType: okhttp3.MediaType get(java.lang.String)>": {
                    HashSet<String> currentArg = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<MediaType> result = new HashSet<>();
                    currentArg.forEach(x -> {
                        try {
                            result.add(MediaType.get(x));
                        } catch (Exception e) {
                            LOGGER.debug("Could not get Header from map");
                        }
                    });
                    return result;
                }
                case "<okhttp3.MediaType: okhttp3.MediaType parse(java.lang.String)>": {
                    HashSet<String> currentArg = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<MediaType> result = new HashSet<>();
                    currentArg.forEach(x -> {
                        try {
                            result.add(MediaType.parse(x));
                        } catch (Exception e) {
                            LOGGER.debug("Could not get Header from map");
                        }
                    });
                    return result;
                }
                case "<okhttp3.Headers$Builder: okhttp3.Headers build()>": {
                    return buildHttpHeaders(((InstanceInvokeExpr) expr).getBase(), currentValues);
                }
                case "<okhttp3.Headers$Builder: okhttp3.Headers$Builder add(java.lang.String)>": {
                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    return addStringHeaders(((InstanceInvokeExpr) expr).getBase(), arg0, currentValues);
                }
                case "<okhttp3.Headers$Builder: okhttp3.Headers$Builder set(java.lang.String,java.lang.String)>":
                case "<okhttp3.Headers$Builder: okhttp3.Headers$Builder addUnsafeNonAscii(java.lang.String,java.lang.String)>":
                case "<okhttp3.Headers$Builder: okhttp3.Headers$Builder add(java.lang.String,java.lang.String)>": {
                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    return addHeadersToBuilder(((InstanceInvokeExpr) expr).getBase(), arg0, arg1, currentValues);
                }
                case "<okhttp3.Headers$Builder: okhttp3.Headers$Builder add(okhttp3.Headers)>": {
                    HashSet<Headers> arg0 = SimulationUtil.getOkhttp3Headers(expr.getArg(0), currentValues);
                    return addHeaders(((InstanceInvokeExpr) expr).getBase(), arg0, currentValues);
                }
                case "<okhttp3.Headers: okhttp3.Headers of(java.lang.String[])>": {
                    HashSet<List<String>> currentArg = SimulationUtil.getStringArrayContent(expr.getArg(0), currentValues);
                    HashSet<Headers> result = new HashSet<>();
                    currentArg.forEach(x -> {
                        try {
                            result.add(Headers.of(x.toArray(new String[0])));
                        } catch (Exception e) {
                            LOGGER.debug("Could not get Header from map");
                        }
                    });
                    return result;
                }
                case "<okhttp3.Headers: okhttp3.Headers of(java.util.Map)>": {
                    HashSet<Map> currentArg = SimulationUtil.getMap(expr.getArg(0), currentValues);
                    HashSet<Headers> result = new HashSet<>();
                    currentArg.forEach(x -> {
                        try {
                            result.add(Headers.of(x));
                        } catch (Exception e) {
                            LOGGER.debug("Could not get Header from map");
                        }
                    });
                    return result;
                }
                default:
                    LOGGER.error("{} is currently not supported by the OkHttpSimulation", signature);
                    break;
            }
            return urls;
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


    private HashSet<HttpUrl.Builder> initBuilder() {
        HashSet<HttpUrl.Builder> tmp = new HashSet<>();
        tmp.add(new HttpUrl.Builder());
        return tmp;
    }


    private HashSet<FormBody> formBodyBuilder(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<FormBody.Builder> values = SimulationUtil.getFormBodyBuilder(from, currentValues);
        HashSet<FormBody> result = new HashSet<>();
        values.forEach(u -> {
            if (u != null) {
                try {
                    result.add(u.build());
                } catch (IllegalStateException e) {
                    LOGGER.error("{} some value might not be defined \n", u);
                }
            }
        });
        return result;
    }


    private HashSet<HttpUrl> build(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<HttpUrl.Builder> values = SimulationUtil.getHttpUrlBuilder(from, currentValues);

        HashSet<HttpUrl> result = new HashSet<>();

        values.forEach(u -> {
            if (u != null) {
                try {
                    result.add(u.build());
                } catch (IllegalStateException e) {
                    LOGGER.error("{} some value might not be defined \n", u);
                }
            }
        });
        return result;
    }


    private HashSet<Headers> buildHttpHeaders(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Headers.Builder> values = SimulationUtil.getOkhttp3HeadersBuilder(from, currentValues);

        HashSet<Headers> result = new HashSet<>();

        values.forEach(u -> {
            if (u != null) {
                try {
                    result.add(u.build());
                } catch (IllegalStateException e) {
                    LOGGER.error("{} some value might not be defined \n", u);
                }
            }
        });
        return result;
    }

    private HashSet<Headers.Builder> addHeaders(Value from, HashSet<Headers> headerValues, HashMap<Value, HashSet<?>> currentValues) {
        List<Headers.Builder> builders = Arrays.asList(SimulationUtil.getOkhttp3HeadersBuilder(from, currentValues).toArray(new Headers.Builder[]{}));
        int i = 0;

        HashSet<Headers.Builder> newValues = new HashSet<>();
        for (Headers value : headerValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).addAll(value));
            } else {
                newValues.add(new Headers.Builder().addAll(value));
            }
            i++;
        }
        return newValues;
    }


    private HashSet<Headers.Builder> addStringHeaders(Value from, HashSet<String> headerValues, HashMap<Value, HashSet<?>> currentValues) {
        List<Headers.Builder> builders = Arrays.asList(SimulationUtil.getOkhttp3HeadersBuilder(from, currentValues).toArray(new Headers.Builder[]{}));
        int i = 0;

        HashSet<Headers.Builder> newValues = new HashSet<>();
        for (String value : headerValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).add(value));
            } else {
                newValues.add(new Headers.Builder().add(value));
            }
            i++;
        }
        return newValues;
    }


    private HashSet<Headers.Builder> addHeadersToBuilder(Value from, HashSet<String> param0, HashSet<String> param1, HashMap<Value, HashSet<?>> currentValues) {
        List<Headers.Builder> builders = Arrays.asList(SimulationUtil.getOkhttp3HeadersBuilder(from, currentValues).toArray(new Headers.Builder[]{}));
        int i = 0;

        HashSet<Headers.Builder> newValues = new HashSet<>();
        for (String value0 : param0) {
            for (String value1 : param1) {
                if (value0 == null || value1 == null) {
                    continue;
                }
                if (i < builders.size()) {
                    newValues.add(builders.get(i).add(value0, value1));
                } else {
                    newValues.add(new Headers.Builder().add(value0, value1));
                }

            }
            i++;
        }
        return newValues;
    }


    private HashSet<String> toString(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<HttpUrl.Builder> builders = SimulationUtil.getHttpUrlBuilder(from, currentValues);
        HashSet<String> newValues = new HashSet<>();

        for (HttpUrl.Builder builder : builders) {
            if (builder == null) {
                continue;
            }
            newValues.add(builder.toString());
        }
        return newValues;


    }


    private HashSet<URL> toURL(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<URL> newValues = new HashSet<>();
        HashSet<HttpUrl> builders = SimulationUtil.getHttpUrl(from, currentValues);

        for (HttpUrl builder : builders) {
            if (builder == null) {
                continue;
            }
            newValues.add(builder.url());
        }
        return newValues;


    }


    private HashSet<HttpUrl> url(Value from, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<Request> request = SimulationUtil.getOkHttpRequest(from, currentValues);
        HashSet<HttpUrl> newValues = new HashSet<>();
        for (Request r : request) {
            if (r == null) {
                continue;
            }
            newValues.add(r.url());
        }

        return newValues;
    }


    private HashSet<HttpUrl.Builder> query(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).query(value));
            } else {
                newValues.add(new HttpUrl.Builder().query(value));
            }
            i++;
        }
        return newValues;

    }


    private HashSet<HttpUrl.Builder> port(Value from, HashSet<Integer> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;


        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (Integer value : schemeValues) {
            if (value == null || value < 1) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).port(value));
            } else {
                newValues.add(new HttpUrl.Builder().port(value));
            }

            i++;
        }

        return newValues;
    }


    private HashSet<HttpUrl.Builder> fragment(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).fragment(value));
            } else {
                newValues.add(new HttpUrl.Builder().fragment(value));
            }
            i++;

        }

        return newValues;
    }

    private HashSet<HttpUrl.Builder> password(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).password(value));
            } else {
                newValues.add(new HttpUrl.Builder().password(value));
            }
            i++;
        }

        return newValues;
    }

    private HashSet<HttpUrl.Builder> encodedQuery(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }

            if (i < builders.size()) {
                newValues.add(builders.get(i).encodedQuery(value));
            } else {
                newValues.add(new HttpUrl.Builder().encodedQuery(value));
            }
            i++;
        }
        return newValues;
    }


    private HashSet<HttpUrl.Builder> encodedPath(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            try {
                if (i < builders.size()) {
                    newValues.add(builders.get(i).encodedPath(value));
                } else {
                    newValues.add(new HttpUrl.Builder().encodedPath(value));
                }
            } catch (IllegalArgumentException e) {
                if (i < builders.size()) {
                    newValues.add(builders.get(i));
                }
                LOGGER.error("Invalid encodedPath to add to the HttpUrlBuilder");
            }

            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> encodedPassword(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).encodedPassword(value));
            } else {
                newValues.add(new HttpUrl.Builder().encodedPassword(value));
            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> encodedFragment(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;


        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).encodedFragment(value));
            } else {
                newValues.add(new HttpUrl.Builder().encodedFragment(value));
            }
            i++;
        }
        return newValues;
    }


    private HashSet<FormBody.Builder> addFormBodyValue(Value from, HashSet<String> param0, HashSet<String> param1, HashMap<Value, HashSet<?>> currentValues) {
        List<FormBody.Builder> builders = Arrays.asList(SimulationUtil.getFormBodyBuilder(from, currentValues).toArray(new FormBody.Builder[]{}));
        int i = 0;
        HashSet<FormBody.Builder> newValues = new HashSet<>();
        for (String value0 : param0) {
            for (String value1 : param1) {
                if (value0 == null || value1 == null) {
                    continue;
                }
                if (i < builders.size()) {
                    newValues.add(builders.get(i).add(value0, value1));
                } else {
                    newValues.add(new FormBody.Builder().add(value0, value1));
                }

            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> addEncodedQueryParameter(Value from, HashSet<String> param0, HashSet<String> param1, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;


        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value0 : param0) {
            for (String value1 : param1) {
                if (value0 == null || value1 == null) {
                    continue;
                }
                if (i < builders.size()) {
                    newValues.add(builders.get(i).addEncodedQueryParameter(value0, value1));
                } else {
                    newValues.add(new HttpUrl.Builder().addEncodedQueryParameter(value0, value1));
                }

            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> addEncodedPathSegments(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).addEncodedPathSegments(value));
            } else {
                newValues.add(new HttpUrl.Builder().addEncodedPathSegments(value));
            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> addEncodedPathSegment(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).addEncodedPathSegment(value));
            } else {
                newValues.add(new HttpUrl.Builder().addEncodedPathSegment(value));
            }

            i++;
        }
        return newValues;
    }


    private HashSet<HttpUrl.Builder> addQueryParameter(Value from, HashSet<String> param0, HashSet<String> param1, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value0 : param0) {
            for (String value1 : param1) {
                if (value0 == null || value1 == null) {
                    continue;
                }
                if (i < builders.size()) {
                    newValues.add(builders.get(i).addQueryParameter(value0, value1));
                } else {
                    newValues.add(new HttpUrl.Builder().addQueryParameter(value0, value1));
                }

            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> encodedUsername(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).encodedUsername(value));
            } else {
                newValues.add(new HttpUrl.Builder().encodedUsername(value));
            }
            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> addPathSegment(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            if (i < builders.size()) {
                newValues.add(builders.get(i).addPathSegment(value));
            } else {
                newValues.add(new HttpUrl.Builder().addPathSegment(value));
            }
            i++;
        }
        return newValues;
    }


    private HashSet<HttpUrl.Builder> host(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            try {
                if (i < builders.size()) {
                    newValues.add(builders.get(i).host(value));
                } else {
                    newValues.add(new HttpUrl.Builder().host(value));
                }
            } catch (IllegalArgumentException e) {
                if (i < builders.size()) {
                    newValues.add(builders.get(i));
                }
                LOGGER.error("Invalid host to add to the HttpUrlBuilder");
            }

            i++;
        }
        return newValues;
    }

    private HashSet<HttpUrl.Builder> scheme(Value from, HashSet<String> schemeValues, HashMap<Value, HashSet<?>> currentValues) {
        List<HttpUrl.Builder> builders = Arrays.asList(SimulationUtil.getHttpUrlBuilder(from, currentValues).toArray(new HttpUrl.Builder[]{}));
        int i = 0;

        HashSet<HttpUrl.Builder> newValues = new HashSet<>();
        for (String value : schemeValues) {
            if (value == null) {
                continue;
            }
            try {
                if (i < builders.size()) {
                    newValues.add(builders.get(i).scheme(value));
                } else {
                    newValues.add(new HttpUrl.Builder().scheme(value));
                }
            } catch (IllegalArgumentException e) {
                if (i < builders.size()) {
                    newValues.add(builders.get(i));
                }
                LOGGER.error("Invalid scheme to add to the HttpUrlBuilder");
            }

            i++;
        }
        return newValues;
    }


}
