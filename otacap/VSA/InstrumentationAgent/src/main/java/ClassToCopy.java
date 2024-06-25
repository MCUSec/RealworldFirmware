public class ClassToCopy {

    /**
     * Sample hash code function, which is added to other classes without hash code function
     * @return hash code of class
     */
    @Override
    public int hashCode() {
        return InstrumentationHelper.getHashCode(this, 0);
    }
    /**
     * Sample  code function, which is added to other classes without hash code function
     * @return true if objects equal
     */
    @Override
    public boolean equals(Object o) {
        return InstrumentationHelper.getObjectsEqual(this, o, 0);
    }

    /**
     * Sample toString function, which is added to other classes without hash code function
     * @return the String representation of the object
     */
    @Override
    public String toString() {
        return InstrumentationHelper.getToString(this, 0);
    }
}

