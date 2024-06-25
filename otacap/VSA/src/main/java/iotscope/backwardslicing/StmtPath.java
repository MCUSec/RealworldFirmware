package iotscope.backwardslicing;

import iotscope.base.StmtPoint;
import soot.Unit;

import java.util.List;

public interface StmtPath {

    Unit getStmtPathTail();

    List<StmtPoint> getStmtPath();
}
