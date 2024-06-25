package iotscope.utility;

import org.javatuples.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Body;
import soot.Unit;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.CompleteBlockGraph;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

public class BlockGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(BlockGenerator.class);

    private static final BlockGenerator blockGenerator = new BlockGenerator();

    public static BlockGenerator getInstance() {
        return blockGenerator;
    }

    private BlockGenerator() {
    }

    private final Hashtable<Body, CompleteBlockGraph> bodyCompleteBlockGraphHashtable = new Hashtable<>();


    public CompleteBlockGraph generate(Body body, Boolean reBuild) {
        if (!bodyCompleteBlockGraphHashtable.containsKey(body) || reBuild) {
            bodyCompleteBlockGraphHashtable.put(body, new CompleteBlockGraph(body));
        }
        return bodyCompleteBlockGraphHashtable.get(body);
    }

    /**
     * @param current            Block to check
     * @param completeBlockGraph blockGraph
     * @param history            of the circle check
     * @return true if there is a circle found
     */
    public static boolean isCircle(Block block, Block current, CompleteBlockGraph completeBlockGraph, HashSet<Block> history) {
        if (history.contains(current)) {
            return false;
        }
        history.add(current);
        for (Block tmpBlock : completeBlockGraph.getPredsOf(current)) {
            if (block == tmpBlock)
                return true;
            if (isCircle(block, tmpBlock, completeBlockGraph, history))
                return true;
        }
        return false;
    }


    public static List<Block> removeBlocksThatHaveBeenVisitedOnce(ArrayList<Pair<Block, Integer>> blocks, List<Block> targets) {
        ArrayList<Pair<Block, Integer>> visitedBlocksSameLayer = new ArrayList<>();
        //current block
        visitedBlocksSameLayer.add(blocks.get(0));
        //current block
        Pair<Block, Integer> currentBlock = blocks.get(0);
        int blocklen = blocks.size();
        boolean iwasInOthersubcall = false;
        for (int index = 1; index < blocklen; index++) {

            visitedBlocksSameLayer.add(blocks.get(index));
        }

        if (iwasInOthersubcall)
            LOGGER.warn("looks like call stack not even");

        List<Block> result = new ArrayList<>();
        for (Block target : targets) {
            int visitedTimes = 0;
            for (Pair<Block, Integer> visitedBlock : visitedBlocksSameLayer) {
                if (visitedBlock.getValue0().equals(target)) {
                    visitedTimes++;
                    break;
                }

            }
            if (visitedTimes < 1)
                result.add(target);
        }

        return result;
    }

    /**
     * Find the block in the control flow graph that contains a particular unit
     * @param cbg
     * @param unit
     * @return
     */
    public static Block findLocatedBlock(CompleteBlockGraph cbg, Unit unit) {

		for (Block block : cbg.getBlocks()) {
			Iterator<Unit> us = block.iterator();
			while (us.hasNext()) {
				if (us.next() == unit) {
					return block;
				}
			}
		}
		return null;

	}

}
