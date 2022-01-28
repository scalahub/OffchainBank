package kiosk.avltree

import kiosk.appkit.Client
import kiosk.ergo.{ByteArrayToBetterByteArray, DhtData, KioskAvlTree, KioskBox, KioskCollByte}
import kiosk.tx.TxUtil
import org.ergoplatform.appkit.{BlockchainContext, ConstantsBuilder, HttpClientTesting, InputBox}
import org.scalatest.{Matchers, PropSpec}
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert}
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.hash.{Blake2b256, Digest32}
import supertagged.@@

class AvlInsertSpec extends PropSpec with Matchers with ScalaCheckDrivenPropertyChecks with HttpClientTesting {
  property("Insert") {

    val ergoClient = createMockedErgoClient(MockData(Nil, Nil))

    ergoClient.execute { implicit ctx: BlockchainContext =>
      val minStorageRent = 1000000L

      val dummyNanoErgs = 10000000000000L
      val dummyScript = "sigmaProp(true)"
      val dummyTxId = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b809"
      val dummyIndex = 1.toShort

      val changeAddress = "9f5ZKbECVTm25JTRQHDHGM5ehC8tUw5g1fCBQ4aaE792rWBFrjK"

      val fundingBox = ctx // for funding transactions
        .newTxBuilder()
        .outBoxBuilder
        .value(dummyNanoErgs)
        .contract(ctx.compileContract(ConstantsBuilder.empty(), dummyScript))
        .build()
        .convertToInputWith(dummyTxId, dummyIndex)

      val inBox = TxUtil
        .createTx(
          Array(fundingBox),
          Array[InputBox](),
          Array(
            KioskBox(
              AvlInsert.address,
              minStorageRent,
              registers = Array(),
              tokens = Array()
            )
          ),
          fee = 1000000L,
          changeAddress,
          Array[String](),
          Array[DhtData](),
          false
        )
        .getOutputsToSpend
        .get(0)

      val KL = 32
      val VL = 8

      val dummyKey = ADKey @@ Array.fill(KL)(0.toByte).take(KL)
      val dummyValue = ADValue @@ Array.fill(VL)(1.toByte).take(VL)

      val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
      avlProver.performOneOperation(Insert(dummyKey, dummyValue))
      avlProver.generateProof()

      val digestIn = avlProver.digest
      val inTree = KioskAvlTree(digestIn, KL, Some(VL))

      val newKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(10.toByte).take(KL)
      val newValue = ADValue @@ Array.fill(KL)(20.toByte).take(VL)

      avlProver.performOneOperation(Insert(newKey, newValue))
      val digestOut = avlProver.digest
      val outTree = KioskAvlTree(digestOut, KL, Some(VL))

      val proof: Array[Byte] = avlProver.generateProof()

      TxUtil.createTx(
        Array(
          inBox,
          fundingBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            AvlInsert.address,
            minStorageRent,
            registers = Array(inTree, outTree, KioskCollByte(newKey), KioskCollByte(newValue), KioskCollByte(proof)),
            tokens = Array()
          )
        ),
        fee = 1000000L,
        changeAddress,
        Array[String](),
        Array[DhtData](),
        false
      )
    }
  }

  ignore("InsertProd") {

    Client.usingContext { implicit ctx: BlockchainContext =>
      val minStorageRent = 1000000L

      val inBoxId = "7db2dd80ebebeaee2c3604899756ed9f6de38fa345297048af3e2135794627e9"
      val fundingBoxId = "e66cf079119f0660eee247ea00609d113a62b39c53109ff159255a55821db40b"

      val changeAddress = "9gQqZyxyjAptMbfW1Gydm3qaap11zd6X9DrABwgEE9eRdRvd27p"

      val proveDlogSecret = "-21120845569549261709579423621450797100274242707397768518154077936446211979699"

      val boxes = ctx.getBoxesById(inBoxId, fundingBoxId)
      val inBox: InputBox = boxes(0)
      val fundingBox: InputBox = boxes(1)

      val KL = 32
      val VL = 8

      val dummyKey = ADKey @@ Array.fill(KL)(0.toByte).take(KL)
      val dummyValue = ADValue @@ Array.fill(VL)(1.toByte).take(VL)

      val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
      avlProver.performOneOperation(Insert(dummyKey, dummyValue))
      avlProver.generateProof()

      val digestIn = avlProver.digest
      val inTree = KioskAvlTree(digestIn, KL, Some(VL))

      val newKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(10.toByte).take(KL)
      val newValue = ADValue @@ Array.fill(KL)(20.toByte).take(VL)

      avlProver.performOneOperation(Insert(newKey, newValue))
      val digestOut = avlProver.digest
      val outTree = KioskAvlTree(digestOut, KL, Some(VL))

      val proof: Array[Byte] = avlProver.generateProof()

      TxUtil.createTx(
        Array(
          inBox,
          fundingBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            AvlInsert.address,
            minStorageRent,
            registers = Array(inTree, outTree, KioskCollByte(newKey), KioskCollByte(newValue), KioskCollByte(proof)),
            tokens = Array()
          )
        ),
        fee = 1000000L,
        changeAddress,
        Array[String](proveDlogSecret),
        Array[DhtData](),
        true
      )
    }
  }

  ignore("InsertProd 2") {

    Client.usingContext { implicit ctx: BlockchainContext =>
      val minStorageRent = 1000000L

      val inBoxId = "b43541ee7552eb5cdc634134b1cdc7c35af0bfe9cb029faec695262212590624"
      val fundingBoxId = "92a011a8a068eea2a5d4d4f510fa07269bb2c273194ea8c79d9cbf27dd19071f"

      val changeAddress = "9gQqZyxyjAptMbfW1Gydm3qaap11zd6X9DrABwgEE9eRdRvd27p"

      val proveDlogSecret = "-21120845569549261709579423621450797100274242707397768518154077936446211979699"

      val boxes = ctx.getBoxesById(inBoxId, fundingBoxId)
      val inBox: InputBox = boxes(0)
      val fundingBox: InputBox = boxes(1)

      val KL = 32
      val VL = 8

      val dummyKey = ADKey @@ Array.fill(KL)(0.toByte).take(KL)
      val dummyValue = ADValue @@ Array.fill(VL)(1.toByte).take(VL)

      val newKey1: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(10.toByte).take(KL)
      val newValue1 = ADValue @@ Array.fill(KL)(20.toByte).take(VL)

      val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
      avlProver.performOneOperation(Insert(dummyKey, dummyValue))
      avlProver.performOneOperation(Insert(newKey1, newValue1))
      avlProver.generateProof()

      val digestIn = avlProver.digest
      val inTree = KioskAvlTree(digestIn, KL, Some(VL))

      val newKey2: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(30.toByte).take(KL)
      val newValue2 = ADValue @@ Array.fill(KL)(40.toByte).take(VL)

      avlProver.performOneOperation(Insert(newKey2, newValue2))

      val digestOut = avlProver.digest
      val outTree = KioskAvlTree(digestOut, KL, Some(VL))

      val proof: Array[Byte] = avlProver.generateProof()

      TxUtil.createTx(
        Array(
          inBox,
          fundingBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            AvlInsert.address,
            minStorageRent,
            registers = Array(inTree, outTree, KioskCollByte(newKey2), KioskCollByte(newValue2), KioskCollByte(proof)),
            tokens = Array()
          )
        ),
        fee = 1000000L,
        changeAddress,
        Array[String](proveDlogSecret),
        Array[DhtData](),
        true
      )
    }
  }
}
