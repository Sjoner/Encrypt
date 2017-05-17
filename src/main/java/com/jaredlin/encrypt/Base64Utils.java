package com.jaredlin.encrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

/**
 * Created by linmq on 2017/5/9.
 */
public class Base64Utils {

    /** Field BASE64DEFAULTLENGTH */
    public static final int BASE64DEFAULTLENGTH = 76;

    private static final int BASELENGTH = 255;
    private static final int LOOKUPLENGTH = 64;
    private static final int TWENTYFOURBITGROUP = 24;
    private static final int EIGHTBIT = 8;
    private static final int SIXTEENBIT = 16;
    private static final int FOURBYTE = 4;
    private static final int SIGN = -128;
    private static final char PAD = '=';
    private static final byte [] base64Alphabet = new byte[BASELENGTH];
    private static final char [] lookUpBase64Alphabet = new char[LOOKUPLENGTH];
    private static final boolean IGNORE_LINEBREAKS = true;

    static {
        for (int i = 0; i < BASELENGTH; i++) {
            base64Alphabet[i] = -1;
        }
        for (int i = 'Z'; i >= 'A'; i--) {
            base64Alphabet[i] = (byte) (i - 'A');
        }
        for (int i = 'z'; i>= 'a'; i--) {
            base64Alphabet[i] = (byte) (i - 'a' + 26);
        }

        for (int i = '9'; i >= '0'; i--) {
            base64Alphabet[i] = (byte) (i - '0' + 52);
        }

        base64Alphabet['+'] = 62;
        base64Alphabet['/'] = 63;

        for (int i = 0; i <= 25; i++) {
            lookUpBase64Alphabet[i] = (char)('A' + i);
        }

        for (int i = 26,  j = 0; i <= 51; i++, j++) {
            lookUpBase64Alphabet[i] = (char)('a' + j);
        }

        for (int i = 52,  j = 0; i <= 61; i++, j++) {
            lookUpBase64Alphabet[i] = (char)('0' + j);
        }
        lookUpBase64Alphabet[62] = '+';
        lookUpBase64Alphabet[63] = '/';
    }

    private Base64Utils() {
        // we don't allow instantiation
    }

    /**
     * Returns a byte-array representation of a <code>{@link BigInteger}<code>.
     * No sign-bit is output.
     *
     * <b>N.B.:</B> <code>{@link BigInteger}<code>'s toByteArray
     * returns eventually longer arrays because of the leading sign-bit.
     *
     * @param big <code>BigInteger<code> to be converted
     * @param bitlen <code>int<code> the desired length in bits of the representation
     * @return a byte array with <code>bitlen</code> bits of <code>big</code>
     */
    static final byte[] getBytes(BigInteger big, int bitlen) {

        //round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;

        if (bitlen < big.bitLength()) {
            throw new IllegalArgumentException("IllegalBitlength");
        }

        byte[] bigBytes = big.toByteArray();

        if (((big.bitLength() % 8) != 0)
            && (((big.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }

        // some copying needed
        int startSrc = 0;    // no need to skip anything
        int bigLen = bigBytes.length;    //valid length of the string

        if ((big.bitLength() % 8) == 0) {    // correct values
            startSrc = 1;    // skip sign bit

            bigLen--;    // valid length of the string
        }

        int startDst = bitlen / 8 - bigLen;    //pad with leading nulls
        byte[] resizedBytes = new byte[bitlen / 8];

        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, bigLen);

        return resizedBytes;
    }

    protected static final boolean isWhiteSpace(byte octect) {
        return (octect == 0x20 || octect == 0xd || octect == 0xa || octect == 0x9);
    }

    protected static final boolean isPad(byte octect) {
        return (octect == PAD);
    }


    public static final String urlsafeEncode(byte[] binaryData) {
        return encode(binaryData).replace('+','-').replace('/','_');
    }

    /**
     * 不在末尾补 '='  , 需要的decode的时候再补齐
     * @param binaryData
     * @return
     */
    public static final String noPadEncode(byte[] binaryData) {
        String result = encode(binaryData);
        while (result.endsWith("=")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    /**
     * Encode a byte array and fold lines at the standard 76th character unless
     * ignore line breaks property is set.
     *
     * @param binaryData <code>byte[]<code> to be base64 encoded
     * @return the <code>String<code> with encoded data
     */
    public static final String encode(byte[] binaryData) {
        return IGNORE_LINEBREAKS
                ? encode(binaryData, Integer.MAX_VALUE)
                : encode(binaryData, BASE64DEFAULTLENGTH);
    }

    /**
     * Encode a byte array in Base64Utils format and return an optionally
     * wrapped line.
     *
     * @param binaryData <code>byte[]</code> data to be encoded
     * @param length <code>int<code> length of wrapped lines; No wrapping if less than 4.
     * @return a <code>String</code> with encoded data
     */
    public static final String  encode(byte[] binaryData,int length) {
        if (length < 4) {
            length = Integer.MAX_VALUE;
        }

        if (binaryData == null) {
            return null;
        }

        int lengthDataBits = binaryData.length * EIGHTBIT;
        if (lengthDataBits == 0) {
            return "";
        }

        int fewerThan24bits = lengthDataBits % TWENTYFOURBITGROUP;
        int numberTriplets = lengthDataBits / TWENTYFOURBITGROUP;
        int numberQuartet = fewerThan24bits != 0 ? numberTriplets + 1 : numberTriplets;
        int quartesPerLine = length / 4;
        int numberLines = (numberQuartet - 1) / quartesPerLine;
        char encodedData[] = null;

        encodedData = new char[numberQuartet * 4 + numberLines];

        byte k = 0, l = 0, b1 = 0, b2 = 0, b3 = 0;
        int encodedIndex = 0;
        int dataIndex = 0;
        int i = 0;

        for (int line = 0; line < numberLines; line++) {
            for (int quartet = 0; quartet < 19; quartet++) {
                b1 = binaryData[dataIndex++];
                b2 = binaryData[dataIndex++];
                b3 = binaryData[dataIndex++];

                l  = (byte)(b2 & 0x0f);
                k  = (byte)(b1 & 0x03);

                byte val1 = ((b1 & SIGN) == 0) ? (byte)(b1 >> 2): (byte)((b1) >> 2 ^ 0xc0);

                byte val2 = ((b2 & SIGN) == 0) ? (byte)(b2 >> 4) : (byte)((b2) >> 4 ^ 0xf0);
                byte val3 = ((b3 & SIGN) == 0) ? (byte)(b3 >> 6) : (byte)((b3) >> 6 ^ 0xfc);


                encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
                encodedData[encodedIndex++] = lookUpBase64Alphabet[val2 | (k << 4)];
                encodedData[encodedIndex++] = lookUpBase64Alphabet[(l << 2) | val3];
                encodedData[encodedIndex++] = lookUpBase64Alphabet[b3 & 0x3f];

                i++;
            }
            encodedData[encodedIndex++] = 0xa;
        }

        for (; i < numberTriplets; i++) {
            b1 = binaryData[dataIndex++];
            b2 = binaryData[dataIndex++];
            b3 = binaryData[dataIndex++];

            l  = (byte)(b2 & 0x0f);
            k  = (byte)(b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte)(b1 >> 2) : (byte)((b1) >> 2 ^ 0xc0);

            byte val2 = ((b2 & SIGN) == 0) ? (byte)(b2 >> 4) : (byte)((b2) >> 4 ^ 0xf0);
            byte val3 = ((b3 & SIGN) == 0) ? (byte)(b3 >> 6) : (byte)((b3) >> 6 ^ 0xfc);


            encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[(l << 2) | val3];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[b3 & 0x3f];
        }

        // form integral number of 6-bit groups
        if (fewerThan24bits == EIGHTBIT) {
            b1 = binaryData[dataIndex];
            k = (byte) (b1 &0x03);
            byte val1 = ((b1 & SIGN) == 0) ? (byte)(b1 >> 2):(byte)((b1) >> 2 ^ 0xc0);
            encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex++] = PAD;
            encodedData[encodedIndex++] = PAD;
        } else if (fewerThan24bits == SIXTEENBIT) {
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex +1 ];
            l = ( byte ) (b2 & 0x0f);
            k = ( byte ) (b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte)(b1 >> 2) : (byte)((b1) >> 2 ^ 0xc0);
            byte val2 = ((b2 & SIGN) == 0) ? (byte)(b2 >> 4) : (byte)((b2) >> 4 ^ 0xf0);

            encodedData[encodedIndex++] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex++] = lookUpBase64Alphabet[l << 2];
            encodedData[encodedIndex++] = PAD;
        }

        //encodedData[encodedIndex] = 0xa;

        return new String(encodedData);
    }

    public static final byte[] urlsafeDecode(String encoded) throws IllegalArgumentException{
        if (encoded == null) {
            return null;
        }
        return decode(encoded.replace('-', '+').replace('_', '/'));
    }

    /**
     * Decodes Base64Utils data into octets
     *
     * @param encoded String containing base64 encoded data
     * @return byte array containing the decoded data
     * @throws IllegalArgumentException if there is a problem decoding the data
     */
    public static final byte[] decode(String encoded) throws IllegalArgumentException {
        if (encoded == null) {
            return null;
        }
        int padSize = 4 - encoded.length() % 4;
        StringBuilder builder = new StringBuilder();
        builder.append(encoded);
        int index = padSize;
        while (index != 0 && padSize != 4) {
            builder.append("=");
            index--;
        }
        encoded = builder.toString();
        byte[] bytes = new byte[encoded.length()];
        int len = getBytesInternal(encoded, bytes);
        return decodeInternal(bytes, len);
    }

    protected static final int getBytesInternal(String s, byte[] result) {
        int length = s.length();

        int newSize = 0;
        for (int i = 0; i < length; i++) {
            byte dataS = (byte)s.charAt(i);
            if (!isWhiteSpace(dataS)) {
                result[newSize++] = dataS;
            }
        }
        return newSize;
    }

    protected static final byte[] decodeInternal(byte[] base64Data, int len)
            throws IllegalArgumentException {
        // remove white spaces
        if (len == -1) {
            len = removeWhiteSpace(base64Data);
        }

        int yu = len % FOURBYTE;
        if (yu != 0) {//不能被4整数时 , 末尾补 '='
//            byte[] tempData = base64Data;
//            base64Data = new byte[tempData.length + (4 - yu)];
//            System.arraycopy(tempData, 0, base64Data, 0, tempData.length);
//            Arrays.fill(base64Data, tempData.length,base64Data.length-1, (byte) '=');
            throw new IllegalArgumentException("decoding.divisible.four");
            //should be divisible by four
        }

        int numberQuadruple = (len / FOURBYTE);

        if (numberQuadruple == 0) {
            return new byte[0];
        }

        byte decodedData[] = null;
        byte b1 = 0, b2 = 0, b3 = 0, b4 = 0;

        int i = 0;
        int encodedIndex = 0;
        int dataIndex = 0;

        //decodedData = new byte[ (numberQuadruple)*3];
        dataIndex = (numberQuadruple - 1) * 4;
        encodedIndex = (numberQuadruple - 1) * 3;
        //first last bits.
        b1 = base64Alphabet[base64Data[dataIndex++]];
        b2 = base64Alphabet[base64Data[dataIndex++]];
        if ((b1==-1) || (b2==-1)) {
            //if found "no data" just return null
            throw new IllegalArgumentException("decoding.general");
        }


        byte d3, d4;
        b3 = base64Alphabet[d3 = base64Data[dataIndex++]];
        b4 = base64Alphabet[d4 = base64Data[dataIndex++]];
        if ((b3 == -1) || (b4 == -1) ) {
            //Check if they are PAD characters
            if (isPad(d3) && isPad(d4)) {               //Two PAD e.g. 3c[Pad][Pad]
                if ((b2 & 0xf) != 0) { //last 4 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                decodedData = new byte[encodedIndex + 1];
                decodedData[encodedIndex]   = (byte)(b1 << 2 | b2 >> 4) ;
            } else if (!isPad(d3) && isPad(d4)) {               //One PAD  e.g. 3cQ[Pad]
                if ((b3 & 0x3) != 0) { //last 2 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                decodedData = new byte[encodedIndex + 2];
                decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4);
                decodedData[encodedIndex] = (byte)(((b2 & 0xf) << 4) |((b3 >> 2) & 0xf));
            } else {
                //an error  like "3c[Pad]r", "3cdX", "3cXd", "3cXX" where X is non data
                throw new IllegalArgumentException("decoding.general");
            }
        } else {
            //No PAD e.g 3cQl
            decodedData = new byte[encodedIndex+3];
            decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4) ;
            decodedData[encodedIndex++] = (byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            decodedData[encodedIndex++] = (byte)(b3 << 6 | b4);
        }
        encodedIndex = 0;
        dataIndex = 0;
        //the begin
        for (i = numberQuadruple - 1; i > 0; i--) {
            b1 = base64Alphabet[base64Data[dataIndex++]];
            b2 = base64Alphabet[base64Data[dataIndex++]];
            b3 = base64Alphabet[base64Data[dataIndex++]];
            b4 = base64Alphabet[base64Data[dataIndex++]];

            if ((b1 == -1) ||
                (b2 == -1) ||
                (b3 == -1) ||
                (b4 == -1)) {
                //if found "no data" just return null
                throw new IllegalArgumentException("decoding.general");
            }

            decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4) ;
            decodedData[encodedIndex++] = (byte)(((b2 & 0xf) << 4) |((b3 >> 2) & 0xf));
            decodedData[encodedIndex++] = (byte)(b3 << 6 | b4 );
        }
        return decodedData;
    }

    /**
     * Decodes Base64Utils data into outputstream
     *
     * @param base64Data String containing Base64Utils data
     * @param os the outputstream
     * @throws IOException
     */
    public static final void decode(String base64Data, OutputStream os)
            throws IOException {
        byte[] bytes = new byte[base64Data.length()];
        int len = getBytesInternal(base64Data, bytes);
        decode(bytes,os,len);
    }

    /**
     * Decodes Base64Utils data into outputstream
     *
     * @param base64Data Byte array containing Base64Utils data
     * @param os the outputstream
     * @throws IOException
     */
    public static final void decode(byte[] base64Data, OutputStream os)
            throws IOException {
        decode(base64Data,os,-1);
    }

    protected static final void decode(byte[] base64Data, OutputStream os, int len)
            throws IOException {
        // remove white spaces
        if (len == -1) {
            len = removeWhiteSpace(base64Data);
        }

        if (len % FOURBYTE != 0) {
            throw new IllegalArgumentException("decoding.divisible.four");
            //should be divisible by four
        }

        int numberQuadruple = (len / FOURBYTE);

        if (numberQuadruple == 0) {
            return;
        }

        //byte decodedData[] = null;
        byte b1 = 0, b2 = 0, b3 = 0, b4 = 0;

        int i = 0;
        int dataIndex = 0;

        //the begin
        for (i=numberQuadruple - 1; i > 0; i--) {
            b1 = base64Alphabet[base64Data[dataIndex++]];
            b2 = base64Alphabet[base64Data[dataIndex++]];
            b3 = base64Alphabet[base64Data[dataIndex++]];
            b4 = base64Alphabet[base64Data[dataIndex++]];
            if ((b1 == -1) ||
                (b2 == -1) ||
                (b3 == -1) ||
                (b4 == -1) ) {
                //if found "no data" just return null
                throw new IllegalArgumentException("decoding.general");
            }

            os.write((byte)(b1 << 2 | b2 >> 4));
            os.write((byte)(((b2 & 0xf) << 4 ) | ((b3 >> 2) & 0xf)));
            os.write( (byte)(b3 << 6 | b4));
        }
        b1 = base64Alphabet[base64Data[dataIndex++]];
        b2 = base64Alphabet[base64Data[dataIndex++]];

        //  first last bits.
        if ((b1 == -1) || (b2 == -1) ) {
            //if found "no data" just return null
            throw new IllegalArgumentException("decoding.general");
        }

        byte d3, d4;
        b3 = base64Alphabet[d3 = base64Data[dataIndex++]];
        b4 = base64Alphabet[d4 = base64Data[dataIndex++]];
        if ((b3 == -1 ) || (b4 == -1) ) { //Check if they are PAD characters
            if (isPad(d3) && isPad(d4)) {               //Two PAD e.g. 3c[Pad][Pad]
                if ((b2 & 0xf) != 0) { //last 4 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                os.write((byte)(b1 << 2 | b2 >> 4));
            } else if (!isPad(d3) && isPad(d4)) {               //One PAD  e.g. 3cQ[Pad]
                if ((b3 & 0x3 ) != 0) { //last 2 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                os.write((byte)(b1 << 2 | b2 >> 4));
                os.write((byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)));
            } else {
                //an error  like "3c[Pad]r", "3cdX", "3cXd", "3cXX" where X is non data
                throw new IllegalArgumentException("decoding.general");
            }
        } else {
            //No PAD e.g 3cQl
            os.write((byte)(b1 << 2 | b2 >> 4));
            os.write( (byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)));
            os.write((byte)(b3 << 6 | b4));
        }
    }

    /**
     * Decodes Base64Utils data into  outputstream
     *
     * @param is containing Base64Utils data
     * @param os the outputstream
     * @throws IOException
     */
    public static final void decode(InputStream is, OutputStream os)
            throws IOException {
        //byte decodedData[] = null;
        byte b1 = 0, b2 = 0, b3 = 0, b4 = 0;

        int index=0;
        byte[] data = new byte[4];
        int read;
        //the begin
        while ((read = is.read()) > 0) {
            byte readed = (byte)read;
            if (isWhiteSpace(readed)) {
                continue;
            }
            if (isPad(readed)) {
                data[index++] = readed;
                if (index == 3) {
                    data[index++] = (byte)is.read();
                }
                break;
            }

            if ((data[index++] = readed) == -1) {
                //if found "no data" just return null
                throw new IllegalArgumentException("decoding.general");
            }

            if (index != 4) {
                continue;
            }
            index = 0;
            b1 = base64Alphabet[data[0]];
            b2 = base64Alphabet[data[1]];
            b3 = base64Alphabet[data[2]];
            b4 = base64Alphabet[data[3]];

            os.write((byte)(b1 << 2 | b2 >> 4));
            os.write((byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)));
            os.write((byte)(b3 << 6 | b4));
        }

        byte d1 = data[0], d2 = data[1], d3 = data[2], d4 = data[3];
        b1 = base64Alphabet[d1];
        b2 = base64Alphabet[d2];
        b3 = base64Alphabet[d3];
        b4 = base64Alphabet[d4];
        if ((b3 == -1) || (b4 == -1)) { //Check if they are PAD characters
            if (isPad(d3) && isPad(d4)) {               //Two PAD e.g. 3c[Pad][Pad]
                if ((b2 & 0xf) != 0) { //last 4 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                os.write((byte)(b1 << 2 | b2 >> 4));
            } else if (!isPad(d3) && isPad(d4)) {               //One PAD  e.g. 3cQ[Pad]
                b3 = base64Alphabet[d3];
                if ((b3 & 0x3) != 0) { //last 2 bits should be zero
                    throw new IllegalArgumentException("decoding.general");
                }
                os.write((byte)(b1 << 2 | b2 >> 4));
                os.write((byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)));
            } else {
                //an error  like "3c[Pad]r", "3cdX", "3cXd", "3cXX" where X is non data
                throw new IllegalArgumentException("decoding.general");
            }
        } else {
            //No PAD e.g 3cQl
            os.write((byte)(b1 << 2 | b2 >> 4));
            os.write((byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)));
            os.write((byte)(b3 << 6 | b4));
        }
    }

    /**
     * remove WhiteSpace from MIME containing encoded Base64Utils data.
     *
     * @param data  the byte array of base64 data (with WS)
     * @return      the new length
     */
    protected static final int removeWhiteSpace(byte[] data) {
        if (data == null) {
            return 0;
        }

        // count characters that's not whitespace
        int newSize = 0;
        int len = data.length;
        for (int i = 0; i < len; i++) {
            byte dataS = data[i];
            if (!isWhiteSpace(dataS)) {
                data[newSize++] = dataS;
            }
        }
        return newSize;
    }
}
