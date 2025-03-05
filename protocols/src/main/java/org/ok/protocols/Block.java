package org.ok.protocols;

import java.util.function.BiFunction;
import java.util.function.Function;

public class Block {
    private final char[] data;
    private int size;

    public Block(int size) {
        this.size = size;
        data = new char[size];

        for (int i = 0; i < size; i++) {
            data[i] = 0;
        }
    }

    public Block(int sizeBytes, char[] data) {
        this(sizeBytes);
        setData(data);
    }

    public Block(int sizeBytes, String data) {
        this(sizeBytes);
        setData(data);
    }

    public Block(int sizeBytes, byte[] data) {
        this(sizeBytes);
        setData(data);
    }

    private void setData(String data) {
        setData(data.toCharArray());
    }

    private void setData(char[] bytes) {
        for (int i = 0; i < size; i++) {
            if (i < bytes.length) {//This used to be bytes.length - 1
                this.data[i] = bytes[i];
            } else {
                this.data[i] = 0;
            }
        }
    }

    private void setData(byte[] bytes) {
        for (int i = 0; i < size; i++) {
            if (i < bytes.length) {//This used to be bytes.length - 1
                this.data[i] = (char)bytes[i];
            } else {
                this.data[i] = 0;
            }
        }
    }

    public char[] getData() {
        return this.data;
    }

    public int getSizeBytes() {
        return this.size;
    }

    public int getSizeBits() {
        return this.size * 8;
    }

    public Block xor(Block other) {
        Block newBlock = new Block(size);

        for (int i = 0; i < size; i++) {
            newBlock.data[i] = (char) (data[i] ^ other.data[i]);
        }

        return newBlock;
    }

    public Block byteWiseOperation(Function<Character, Character> operation) {
        Block newBlock = new Block(size);

        for (int i = 0; i < size; i++) {
            newBlock.data[i] = operation.apply(data[i]);
        }

        return newBlock;
    }

    public Block rowWiseOperation(BiFunction<Character[], Integer, Character[]> operation) {
        if (Math.sqrt(size) % 1 != 0)
            throw new RuntimeException("Row-wise operations can only be performed on square blocks!");

        int rowLength = (int) Math.sqrt(size);
        Block newBlock = new Block(size);

        for (int i = 0; i < rowLength; i++) {
            Character[] row = new Character[rowLength];

            for (int j = 0; j < rowLength; j++) {
                row[j] = data[j * rowLength + i];
            }

            Character[] newRow = operation.apply(row, i);

            for (int j = 0; j < rowLength; j++) {
                newBlock.data[j * rowLength + i] = newRow[j];
            }
        }

        return newBlock;
    }

    public Block columnWiseOperation(BiFunction<Character[], Integer, Character[]> operation) {
        if (Math.sqrt(size) % 1 != 0)
            throw new RuntimeException("Column-wise operations can only be performed on square blocks!");

        int rowLength = (int) Math.sqrt(size);
        Block newBlock = new Block(size);

        for (int col = 0; col < rowLength; col++) {
            Character[] column = new Character[rowLength];

            for (int row = 0; row < rowLength; row++) {
                column[row] = data[col * rowLength + row];
            }

            Character[] newColumn = operation.apply(column, col);

            for (int row = 0; row < rowLength; row++) {
                newBlock.data[col * rowLength + row] = newColumn[row];
            }
        }

        return newBlock;
    }

}