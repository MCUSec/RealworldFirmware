package iotscope.forwardexec.objectSimulation.network;

import iotscope.forwardexec.objectSimulation.SimulationObjects;
import iotscope.forwardexec.objectSimulation.SimulationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Value;
import soot.jimple.*;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;

public class JavaNetUriSimulation implements SimulationObjects {


    private static final Logger LOGGER = LoggerFactory.getLogger(JavaNetUriSimulation.class);


    public JavaNetUriSimulation() {
    }

    @Override
    public HashSet<?> handleInvokeStmt(InvokeStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        HashSet<URI> uri = new HashSet<>();
        if (signature.contains("java.net.URI")) {
            switch (signature) {
                case "<java.net.URI: void <init>(java.lang.String)>": {
                    HashSet<String> values = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    values.forEach(v -> {
                        try {
                            if (!SimulationUtil.validProtocol(v)) {
                                v = SimulationUtil.addProtocolToString(v);
                            }
                            uri.add(new URI(v));
                        } catch (URISyntaxException | NullPointerException e) {
                            try {
                                uri.add(new URI(SimulationUtil.sanitizeURL(v)));
                            } catch (URISyntaxException | NullPointerException e2) {
                                LOGGER.error(e2.getLocalizedMessage());
                            }
                        }
                    });
                    break;
                }
                case "<java.net.URI: void <init>(java.lang.String,java.lang.String,java.lang.String)>": {

                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                try {
                                    String protocol = v1;
                                    if (!SimulationUtil.validProtocol(protocol)) {
                                        protocol = "unknown";
                                    }
                                    uri.add(new URI(protocol, v2, v3));
                                } catch (URISyntaxException | NullPointerException e) {
                                    try {
                                        String protocol = v1;
                                        if (!SimulationUtil.validProtocol(protocol)) {
                                            protocol = "unknown";
                                        }
                                        uri.add(new URI(protocol, SimulationUtil.findDomain(v2), v3));
                                    } catch (URISyntaxException | NullPointerException e2) {
                                        LOGGER.error(e2.getLocalizedMessage());
                                    }
                                }
                            });
                        });

                    });
                    break;

                }
                case "<java.net.URI: void <init>(java.lang.String,java.lang.String,java.lang.String,int,java.lang.String,java.lang.String,java.lang.String)>": {

                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);
                    HashSet<Integer> arg3 = SimulationUtil.getIntContent(expr.getArg(3), currentValues);
                    HashSet<String> arg4 = SimulationUtil.getStringContent(expr.getArg(4), currentValues);
                    HashSet<String> arg5 = SimulationUtil.getStringContent(expr.getArg(5), currentValues);
                    HashSet<String> arg6 = SimulationUtil.getStringContent(expr.getArg(6), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                arg3.forEach(v4 -> {
                                    arg4.forEach(v5 -> {
                                        arg5.forEach(v6 -> {
                                            arg6.forEach(v7 -> {
                                                try {
                                                    String protocol = v1;
                                                    if (!SimulationUtil.validProtocol(protocol)) {
                                                        protocol = "unknown";
                                                    }
                                                    uri.add(new URI(protocol, v2, v3, v4, v5, v6, v7));
                                                } catch (URISyntaxException | NullPointerException e) {
                                                    try {
                                                        String protocol = v1;
                                                        if (!SimulationUtil.validProtocol(protocol)) {
                                                            protocol = "unknown";
                                                        }
                                                        uri.add(new URI(protocol, SimulationUtil.findDomain(v2), v3, v4, v5, v6, v7));
                                                    } catch (URISyntaxException | NullPointerException e2) {
                                                        LOGGER.error(e2.getLocalizedMessage());
                                                    }
                                                }
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                    break;

                }
                case "<java.net.URI: void <init>(java.lang.String,java.lang.String,java.lang.String,java.lang.String)>": {

                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);
                    HashSet<String> arg3 = SimulationUtil.getStringContent(expr.getArg(3), currentValues);


                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                arg3.forEach(v4 -> {
                                    try {
                                        String protocol = v1;
                                        if (!SimulationUtil.validProtocol(protocol)) {
                                            protocol = "unknown";
                                        }
                                        uri.add(new URI(protocol, v2, v3, v4));
                                    } catch (URISyntaxException | NullPointerException e) {
                                        try {
                                            String protocol = v1;
                                            if (!SimulationUtil.validProtocol(protocol)) {
                                                protocol = "unknown";
                                            }
                                            uri.add(new URI(protocol, SimulationUtil.findDomain(v2), v3, v4));
                                        } catch (URISyntaxException | NullPointerException e2) {
                                            LOGGER.error(e2.getLocalizedMessage());
                                        }
                                    }
                                });
                            });
                        });
                    });
                    break;

                }
                case "<java.net.URI: void <init>(java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>": {

                    HashSet<String> arg0 = SimulationUtil.getStringContent(expr.getArg(0), currentValues);
                    HashSet<String> arg1 = SimulationUtil.getStringContent(expr.getArg(1), currentValues);
                    HashSet<String> arg2 = SimulationUtil.getStringContent(expr.getArg(2), currentValues);
                    HashSet<String> arg3 = SimulationUtil.getStringContent(expr.getArg(3), currentValues);
                    HashSet<String> arg4 = SimulationUtil.getStringContent(expr.getArg(4), currentValues);

                    arg0.forEach(v1 -> {
                        arg1.forEach(v2 -> {
                            arg2.forEach(v3 -> {
                                arg3.forEach(v4 -> {
                                    arg4.forEach(v5 -> {
                                        try {
                                            String protocol = v1;
                                            if (!SimulationUtil.validProtocol(protocol)) {
                                                protocol = "unknown";
                                            }
                                            uri.add(new URI(protocol, v2, v3, v4, v5));
                                        } catch (URISyntaxException | NullPointerException e) {
                                            try {
                                                String protocol = v1;
                                                if (!SimulationUtil.validProtocol(protocol)) {
                                                    protocol = "unknown";
                                                }
                                                uri.add(new URI(protocol, SimulationUtil.findDomain(v2), v3, v4, v5));
                                            } catch (URISyntaxException | NullPointerException e2) {
                                                LOGGER.error(e2.getLocalizedMessage());
                                            }
                                        }
                                    });
                                });
                            });

                        });
                    });
                    break;
                }
            }

        }
        return uri;
    }

    @Override
    public HashSet<?> handleAssignInvokeExpression(AssignStmt stmt, String signature, InvokeExpr expr, HashMap<Value, HashSet<?>> currentValues) {
        if (signature.contains("java.net.URI")) {
            Value to = stmt.getLeftOp();
            HashSet<String> uriString = new HashSet<>();
            if (signature.equals("<java.net.URI: java.lang.String toString()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.toString() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getAuthority()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();

                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getAuthority() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getFragment()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getFragment() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getHost()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getHost() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getPath()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getPath() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getQuery()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getQuery() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawAuthority()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawAuthority() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawFragment()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawFragment() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawPath()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawPath() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawQuery()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawQuery() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawSchemeSpecificPart()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawSchemeSpecificPart() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getRawUserInfo()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawUserInfo() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getScheme()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getScheme() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String getSchemeSpecificPart()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getRawSchemeSpecificPart() : "");
                });
            } else if (signature.equals("<java.net.URI: java.lang.String getUserInfo()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.getUserInfo() : "");
                });

            } else if (signature.equals("<java.net.URI: java.lang.String toASCIIString()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    uriString.add(v != null ? v.toASCIIString() : "");
                });

            } else if (signature.equals("<java.net.URI: java.net.URL toURL()>")) {
                Value from = ((VirtualInvokeExpr) expr).getBase();
                HashSet<URL> uris = new HashSet<>();
                if (currentValues.containsKey(to)) {
                    currentValues.get(to).clear();
                }

                HashSet<URI> urls = SimulationUtil.getJavaNetURI(from, currentValues);
                urls.forEach(v -> {
                    try {
                        uris.add(v != null ? v.toURL() : null);
                    } catch (MalformedURLException e) {
                        //e.printStackTrace();
                        LOGGER.error(e.getLocalizedMessage());
                    }
                });
                return uris;

            } else if (signature.contains("<android.net.Uri: java.lang.String encode(")) {
                return SimulationUtil.getStringContent(expr.getArg(0), currentValues);
            }

            return uriString;
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignConstant(AssignStmt stmt, Value rightValue, Value leftOp, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignNewArrayExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        NewArrayExpr newArrayExpr = ((NewArrayExpr) rightValue);
        if (newArrayExpr.getBaseType().toString().equals("java.net.URI")) {
            return SimulationUtil.initArray(null, newArrayExpr, currentValues);
        }
        return null;
    }


    @Override
    public HashSet<?> handleAssignNewExpression(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

    @Override
    public HashSet<?> handleAssignArithmeticExpr(AssignStmt stmt, Value rightValue, HashMap<Value, HashSet<?>> currentValues) {
        return null;
    }

}
