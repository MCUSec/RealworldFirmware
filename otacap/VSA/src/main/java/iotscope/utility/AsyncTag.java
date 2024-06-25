package iotscope.utility;

import soot.tagkit.Tag;

public class AsyncTag implements Tag{
	private String name;

    public AsyncTag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] getValue() {
        return null;
    }
}