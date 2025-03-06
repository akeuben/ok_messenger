package org.ok.protocols;

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

    public Block(java.security.Key key) {
        this(key.getEncoded().length, key.getEncoded());
    }

    public Block(int sizeBytes, byte[] data) {
        this(sizeBytes);
        setData(data);
    }

    public Block(int sizeBytes, String data) {
        this(sizeBytes);
        setData(data);
    }

    public Block(byte[] data) {
        this(data.length, data);
    }

    public Block(String data) {
        this(data.length(), data);
    }

    public static Block fromHexString(String hexEncodedBlock) {
        byte[] bytes = HexFormat.of().parseHex(hexEncodedBlock);

        return new Block(bytes.length, bytes);
    }

    public Block subData(int start, int end) {
        byte[] data = new byte[end-start];
        System.arraycopy(this.data, start, data, 0, Math.min(end-start, this.data.length));
        return new Block(data.length, data);
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

    public Block pkcs7Pad(int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];

        // Copy original data
        System.arraycopy(data, 0, paddedData, 0, data.length);

        // Fill padding bytes with the padding value
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingLength;
        }

        return new Block(paddedData);
    }

    public Block pkcs7Unpad(int blockSize) {
        int paddingLength = this.data[this.data.length - 1] & 0xFF; // Convert to unsigned

        // Validate padding (ensure all padding bytes have the correct value)
        if (paddingLength < 1 || paddingLength > blockSize) {
            throw new RuntimeException("Invalid PKCS#7 padding");
        }

        for (int i = 1; i <= paddingLength; i++) {
            if (this.data[this.data.length - i] != (byte) paddingLength) {
                throw new RuntimeException("Invalid PKCS#7 padding");
            }
        }

        // Remove padding
        byte[] unpaddedData = new byte[this.data.length - paddingLength];
        System.arraycopy(this.data, 0, unpaddedData, 0, unpaddedData.length);
        return new Block(unpaddedData);
    }


    @Override
    public String toString() {
        StringBuilder hex = new StringBuilder();
        for (byte datum : data) {
            hex.append(HexFormat.of().toHexDigits(datum));
        }

        return hex.toString();
    }

    public static Block concat(Block ...blocks) {
        int size = 0;
        for(int i = 0; i < blocks.length; i++) {
            size += blocks[i].size;
        }

        byte[] resultData = new byte[size];

        int start = 0;
        for(int i = 0; i < blocks.length; i++) {
            System.arraycopy(blocks[i].data, 0, resultData, start, blocks[i].getSizeBytes());
            start += blocks[i].getSizeBytes();
        }
        return new Block(resultData.length, resultData);
    }
}