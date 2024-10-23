import { hash256, Sha256, toByteString } from 'scrypt-ts';
import { MerkleProof, Node, NodePos, MERKLE_PROOF_MAX_DEPTH } from '../../src/contracts/merklePath';

export class MerkleTree {
    levels: Sha256[][];

    constructor() {
        this.levels = [];
    }

    // Add a level to the tree
    addLevel(level: Sha256[]) {
        this.levels.push(level);
    }

    // Get the Merkle root (top of the tree)
    getRoot(): Sha256 {
        return this.levels[this.levels.length - 1][0];
    }

    // Get the full tree
    getTree(): Sha256[][] {
        return this.levels;
    }

    // Get a Merkle proof for a given leaf index
    getMerkleProof(leafIndex: number): MerkleProof {
        const proof: Node[] = [];
        let index = leafIndex;

        for (let level = 0; level < this.levels.length - 1; level++) {
            const levelHashes = this.levels[level];
            const isRightNode = index % 2 === 1;
            const siblingIndex = isRightNode ? index - 1 : index + 1;

            if (siblingIndex < levelHashes.length) {
                proof.push({
                    hash: levelHashes[siblingIndex],
                    pos: isRightNode ? NodePos.Left : NodePos.Right
                });
            } else {
                proof.push({
                    hash: toByteString(''),
                    pos: NodePos.Invalid
                });
            }

            index = Math.floor(index / 2);
        }

        // Pad with invalid nodes if proof is shorter than max depth
        while (proof.length < MERKLE_PROOF_MAX_DEPTH) {
            proof.push({
                hash: toByteString(''),
                pos: NodePos.Invalid
            });
        }

        return proof as MerkleProof;
    }
    
    
    // Update a leaf and recalculate the tree
    updateLeaf(leafIndex: number, newValue: Sha256) {
        const numLevels = this.levels.length;
        this.levels[0][leafIndex] = newValue; // Update the leaf with the new hash

        // Recalculate the tree from the updated leaf upwards
        let index = leafIndex;
        for (let level = 0; level < numLevels - 1; level++) {
            const currentLevel = this.levels[level];
            const nextLevel = this.levels[level + 1];

            // Determine sibling index and compute the new hash for the parent node
            const isRightNode = index % 2 === 1;
            const siblingIndex = isRightNode ? index - 1 : index + 1;

            const left = isRightNode ? currentLevel[siblingIndex] : currentLevel[index];
            const right = isRightNode ? currentLevel[index] : currentLevel[siblingIndex];

            const parentIndex = Math.floor(index / 2);
            nextLevel[parentIndex] = hash256(left + right);

            // Move to the next level up
            index = parentIndex;
        }
    }
}

export function buildMerkleTree(leaves: Sha256[], tree: MerkleTree): Sha256[] {
    tree.addLevel(leaves);

    if (leaves.length === 1) {
        return leaves;
    }

    const nextLevel: Sha256[] = [];

    for (let i = 0; i < leaves.length; i += 2) {
        const left = leaves[i];
        const right = i + 1 < leaves.length ? leaves[i + 1] : leaves[i];
        const combinedHash = hash256(left + right);
        nextLevel.push(combinedHash);
    }

    return buildMerkleTree(nextLevel, tree);
}
