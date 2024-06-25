package iotscope.utility;

import java.util.ArrayList;
import java.util.List;

public class General {
    private static final List<String> exclusionList = new ArrayList<>();

    static {
        // Initialize and sort the list
        exclusionList.add("android.");
        exclusionList.add("androidx.");
        exclusionList.add("com.alibaba.");
        exclusionList.add("com.bumptech.glide.");
        exclusionList.add("com.facebook.");
        exclusionList.add("com.fasterxml.jackson.");
        exclusionList.add("com.google.");
        exclusionList.add("com.google.gson.");
        exclusionList.add("com.google.protobuf.");
        exclusionList.add("java.");
        exclusionList.add("javax.");
        exclusionList.add("junit.");
        exclusionList.add("kotlin.");
        exclusionList.add("kotlinx.");
        exclusionList.add("okhttp3.");
        exclusionList.add("okio.");
        exclusionList.add("org.apache.");
        exclusionList.add("org.bouncycastle.");
        exclusionList.add("org.eclipse.");
        exclusionList.add("org.intellij.lang.");
        exclusionList.add("org.jetbrains.");
        exclusionList.add("org.json.");
        exclusionList.add("org.junit.");
        exclusionList.add("org.spongycastle.");
        exclusionList.add("retrofit.");
        exclusionList.add("retrofit2.");
        exclusionList.add("rx.");
        exclusionList.add("soot.");
        exclusionList.add("sun.");
    }

    public static boolean startsWithAny(String element) {
        for (String prefix : exclusionList) {
            if (element.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
