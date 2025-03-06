package org.ok.protocols;

import org.ok.protocols.aes.AESKey;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.function.BiFunction;
import java.util.function.Function;

public class Block {
    private final byte[] data;
    private int size;

    public Block(int size) {
        this.size = size;
        data = new byte[size];

        for(int i = 0; i < size; i++) {
            data[i] = 0;
        }
    }

    public Block(int sizeBytes, String data) {
        this(sizeBytes);
        setData(data);
    }
    public Block(int sizeBytes, byte[] data) {
        this(sizeBytes);
        setData(data);
    }



    public static Block fromHexString(String hexEncodedBlock) {
        byte[] bytes = HexFormat.of().parseHex(hexEncodedBlock);

        return new Block(bytes.length, bytes);
    }

    private void setData(String data) {
        setData(data.getBytes(StandardCharsets.US_ASCII));
    }

    private void setData(byte[] bytes) {
        for(int i = 0; i < size; i++) {
            if(i < bytes.length) {
                this.data[i] = bytes[i];

            } else {
                this.data[i] = 0;
            }
        }
    }

    public byte[] getData() {
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

        for(int i = 0; i < size; i++) {
            newBlock.data[i] = (byte) (data[i] ^ other.data[i]);
        }

        return newBlock;
    }

    public Block byteWiseOperation(Function<Byte, Byte> operation) {
        Block newBlock = new Block(size);

        for(int i = 0; i < size; i++) {
            newBlock.data[i] = operation.apply(data[i]);
        }

        return newBlock;
    }

    public Block rowWiseOperation(BiFunction<Byte[], Integer, Byte[]> operation) {
        if (Math.sqrt(size) % 1 != 0)
            throw new RuntimeException("Row-wise operations can only be performed on square blocks!");

        int rowLength = (int) Math.sqrt(size);
        Block newBlock = new Block(size);

        for (int i = 0; i < rowLength; i++) {
            Byte[] row = new Byte[rowLength];

            for (int j = 0; j < rowLength; j++) {
                row[j] = data[j * rowLength + i];
            }

            Byte[] newRow = operation.apply(row, i);

            for (int j = 0; j < rowLength; j++) {
                newBlock.data[j * rowLength + i] = newRow[j];
            }
        }

        return newBlock;
    }

    public Block columnWiseOperation(BiFunction<Byte[], Integer, Byte[]> operation) {
        if (Math.sqrt(size) % 1 != 0)
            throw new RuntimeException("Column-wise operations can only be performed on square blocks!");

        int rowLength = (int) Math.sqrt(size);
        Block newBlock = new Block(size);

        for (int col = 0; col < rowLength; col++) {
            Byte[] column = new Byte[rowLength];

            for (int row = 0; row < rowLength; row++) {
                column[row] = data[col * rowLength + row];
            }

            Byte[] newColumn = operation.apply(column, col);

            for (int row = 0; row < rowLength; row++) {
                newBlock.data[col * rowLength + row] = newColumn[row];
            }
        }

        return newBlock;
    }


    @Override
    public boolean equals(Object obj) {
        if(obj instanceof Block other) {
            if(other.data.length != data.length) {
                return false;
            }
            for (int i = 0; i < other.data.length; i++) {
                if(other.data[i] != data[i]) return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        StringBuilder hex = new StringBuilder();
        for (byte datum : data) {
            hex.append(HexFormat.of().toHexDigits(datum));
        }

        return hex.toString();
    }
}
