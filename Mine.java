// CS1699[Laboon] - Blockchain & Cryptocurrency
// Project #2 - Mine.java
// Brandon La - bnl22@pitt.edu

// Candidate Block Requirements
// 1. Hash of block MUST meet dificulty (second argument)
// 2. Size of 'nonce' filed is 4 characters; no more or less
// 3. Size limit to block = 16 (15 + initial coinbase transaction)
// 4. MUST contain at least one transaction (not including coinbase transaction)
// 5. Single coinbase transaction MUST be included

import java.util.*;
import java.io.*;
import java.security.*;
import java.nio.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.lang.*;


class Sha256Hash {
    /**
     * Given some arbitrary byte array bytes, convert it to a hex string.
     * Example: [0xFF, 0xA0, 0x01] -> "FFA001"
     * @param bytes arbitrary-length array of bytes
     * @return String hex string version of byte array
     */
    private static String convertBytesToHexString(byte[] bytes) {
        StringBuffer toReturn = new StringBuffer();
        for (int j = 0; j < bytes.length; j++) {
            String hexit = String.format("%02x", bytes[j]);
            toReturn.append(hexit);
        }
        return toReturn.toString();
    }


    /**
     * Given some string, return the SHA256 hash of it.
     * @param x Arbitrary string
     * @return String Hex version of the hash of that object's data
     */
    public static String calculateHash(String x) {
        if (x == null) {
            return "0";
        }
        byte[] hash = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(x.getBytes());
        } catch (NoSuchAlgorithmException nsaex) {
            System.err.println("No SHA-256 algorithm found.");
            System.err.println("This generally should not happen...");
            System.exit(1);
        }
        return convertBytesToHexString(hash);
    }

    /**
     * Given a string, returns the hash as a BigInteger
     * @param toHash - string to hash
     * @return BigInteger - hash of String toHash
     * @see calculateHash method, above
     */
    public static BigInteger hashBigInteger(String toHash) {
        return new BigInteger(calculateHash(toHash), 16);
    }	
}

class Miner {
	 /**
     * This increments our String nonce by accepting a String version
     * and returning a String version.  For example:
     * "000A" -> "000B"
     * "FFFE" -> "FFFF"
     * @param nonce initial nonce
     * @return nonce incremented by one in string form
     */
    public static String incrementStringNonce(String nonce) {
        BigInteger bi = new BigInteger(nonce, 16);
        bi = bi.add(BigInteger.ONE);
        return bi.toString(16);
    }

    /**
     * Prepend a string with 0's until it is of length n.
     * Useful for printing out hash results.
     * @param str String to prepend 0's to
     * @param n correct size of string after being padded
     * @return String str left-padded with 0's
     */
    public static String leftPad(String str, int n) {
        return String.format("%1$" + n + "s", str).replace(' ', '0');
    }

    /**
     * Given a start time and end time in nanoseconds (courtesy of System.nanoTime),
     * and a number of hashes complete in this time, print out the number of hashes
     * per second.
     * @param numHashes - number of hashes completed
     * @param startTime - time hashing started
     * @param endTime - time hashing ended
     */
    public static void printHashRate(BigInteger numHashes, long startTime, long endTime){
        long timeDiff = endTime - startTime;
        long seconds = timeDiff / 1000000000;
        BigInteger time = new BigInteger ((Long.valueOf(seconds)).toString());
        //BigInteger hashesPerSecond = numHashes.divide(time);
        System.out.println("Time: " + time);
    }
}

class Transaction {
	// the entire transaction string from file
	String entireTransaction;

	// initializing # of inputs/outputs
	int numTransactions;

	// initializing miner's payout
	int minerPayout;

	// processing transaction file's information
	public Transaction(String line){

		// save list of all transactions
		entireTransaction = line;

		// swtich for available fees
		boolean ioAvailable = false; 

		// switch for inputs
		boolean input = true;

		// temporary string to store the remaining transactions
		String tempAvailable = "";

		// converting to character array for easier string manipulation
		char[] temp = line.toCharArray();

		for (int i = 0; i < temp.length; i++) {

			// if a fee is present
			if (ioAvailable) {

				tempAvailable += temp[i];

				// perform a check to see if there anymore transactions
				if (i == temp.length - 1 || temp[i + 1] == ',' || temp[i + 1] == ';') {

					ioAvailable = false;
					// increment number of transactions
					numTransactions++;

					if (!input) {
						minerPayout -= Integer.parseInt(tempAvailable);
					}
					else {
						minerPayout += Integer.parseInt(tempAvailable);
					}
					tempAvailable = "";

					if (i != temp.length - 1) {
						if (temp[i + 1] == ';') {
							input = false;
						}
					}
				}
			}
			if (temp[i] == '>') {
				ioAvailable = true;
			}
		}
	}

	public String getEntireTransaction() {
		return entireTransaction;
	}
	public int getTransactionCount() {
		return numTransactions;
	}
	public int getMinerPayout() {
		return minerPayout;
	}
}

public class Mine {

	public static int transactionCount = 0;
	public static final BigInteger MAX_TARGET = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

	public static LinkedList<Transaction> initializeTransactions(String file) throws Exception{

		// place transactions into linked list
		LinkedList<Transaction> transactions = new LinkedList<>();

		// iterator for transaction list
		String currentLine;

		int count = 0;

		Scanner scanny = new Scanner(new File(file));

		// read in the file
		while(scanny.hasNextLine()) {
			count++;
			currentLine = scanny.nextLine();

			transactions.add(new Transaction(currentLine));
		}

		if (count == 0) {
			System.out.println("~At least 1 transaction must exist~");
			System.exit(0);
		}
		scanny.close();
		return transactions;
	}

	// store entire transaction list and search for best combinations of transactions for maximum fees and still be <= 15
	public static LinkedList<Transaction> sortedTransactions(LinkedList<Transaction> total){

		LinkedList<Transaction> sortedTransactions = new LinkedList<>();

		int count = 0;
		int inputOutputs = 0;

		// total maximum # of transactions included in the block must be 16, so we need 15 + 1 (from Bill)
		while (count < total.size() && inputOutputs < 15) {

			Transaction currentTransaction = total.get(count++);
			if (currentTransaction.getTransactionCount() + inputOutputs <= 15) {
				sortedTransactions.add(currentTransaction);
				inputOutputs += currentTransaction.getTransactionCount();
			}
		}
		transactionCount = inputOutputs;

		return sortedTransactions;
	}


	public static void main(String args[]) throws Exception{

		if(args.length != 3) {
			System.out.println("Need more arguments plzzz");
			System.out.println("Usage: *candidate_transaction_file* *difficulty* *prev_hash*");
			System.exit(1);
		}

		BigInteger difficulty = new BigInteger(args[1]);
		BigInteger target = MAX_TARGET.divide(difficulty);

		// store transactions into linked list
		LinkedList<Transaction> transactions = initializeTransactions(args[0]);

		// store transactions into sorted list to determine best transactions
		LinkedList<Transaction> sortedTransactions = sortedTransactions(transactions);

		// initialize miner's payout of 50 BillCoins
		int minerProfit = 50;
		int numRewards = 0;
		int concatCount = 0;

		String nonce = "0";
		String concat = "";
		String currentTime;

		while (numRewards < sortedTransactions.size()) {
			Transaction check = sortedTransactions.get(numRewards++);

			// add on remaining payouts
			minerProfit += check.getMinerPayout();
			// System.out.println("YERRRRR:" + minerProfit);
		}

		// add initial base transaction to the list of transations
		sortedTransactions.add(new Transaction(";1333dGpHU6gQShR596zbKHXEeSihdtoyLb>" + String.valueOf(minerProfit)));
		transactionCount += 1;

		// initialize the concatenation of all transactions
		StringBuilder concatRoot = new StringBuilder();

		while (concatCount < sortedTransactions.size()) {
			Transaction currentTransaction = sortedTransactions.get(concatCount++);
			concatRoot.append(currentTransaction.getEntireTransaction());
		}
		// concatenation of all of the transactions to create "Concat Root"
		String transactionBlock = concatRoot.toString();

		// hash of concatenated root
		String concatHash = Sha256Hash.calculateHash(transactionBlock);

		// sort transactions to maximize payout
		Collections.sort(transactions, new Comparator<Transaction>(){
			@Override
			public int compare(Transaction one, Transaction two){
				return two.minerPayout = one.minerPayout;
			}
		});

		while (true) {

			// concatenate the nonce
			concat = (Miner.leftPad(nonce, 64));

			// retrieve current time since epoch and convert to milliseconds
			currentTime = Long.toString(System.currentTimeMillis());

			// hash together the entire block
			BigInteger blockHash = Sha256Hash.hashBigInteger(args[2] + transactionCount + currentTime + args[1] + concat + concatHash);

			// if our hash is less than the target, proceed to output block information
			if (blockHash.compareTo(target) == -1) {
				// Hash of Candidate Block
				System.out.println("\nCANDIDATE BLOCK = Hash " + Miner.leftPad(blockHash.toString(16), 64));

				System.out.println("----------------------------------------------------");

				// Previous Hash
				System.out.println(args[2]);

				// # of Transaction inputs/outputs
				System.out.println(transactionCount);

				// Current timestamp in milliseconds
				System.out.println(currentTime);

				// Difficulty
				System.out.println(args[1]);

				// Nonce
				System.out.println(nonce);

				//Concatenated root of sorted transactions
				System.out.println(concatHash);

				// System.out.println("List of Transactions: ");

				// print the entire transaction list
				for (int i = 0; i < sortedTransactions.size(); i++) {
					Transaction transactionIterator = sortedTransactions.get(i);
					System.out.println(transactionIterator.getEntireTransaction());
				}

				break;
			}
			else {
                // Uncomment to see failed attempts
                // System.out.println("Fail, hash "
                //            + leftPad(hash.toString(16), 64) + " >= "
                //            + leftPad(target.toString(16), 64));

                // if the nonce is larger than 4, then reset it and continue looking for nonces
                if (nonce.length() > 4) {
                	nonce = "0";
                }
                nonce = Miner.incrementStringNonce(nonce);
			}
		}

		System.exit(0);
	}
}