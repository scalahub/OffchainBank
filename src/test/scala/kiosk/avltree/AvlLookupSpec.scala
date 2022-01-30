package kiosk.avltree

import kiosk.appkit.Client
import kiosk.ergo.{ByteArrayToBetterByteArray, DhtData, KioskAvlTree, KioskBox, KioskCollByte}
import kiosk.tx.TxUtil
import org.ergoplatform.appkit.{BlockchainContext, ConstantsBuilder, HttpClientTesting, InputBox}
import org.scalatest.{Matchers, PropSpec}
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert, Lookup, Remove}
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.hash.{Blake2b256, Digest32}
import supertagged.@@

class AvlLookupSpec extends PropSpec with Matchers with ScalaCheckDrivenPropertyChecks with HttpClientTesting {
  property("Lookup") {

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
              AvlLookup.address,
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

      val newKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(10.toByte).take(KL)
      val newValue = ADValue @@ Array.fill(KL)(20.toByte).take(VL)

      val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))

      avlProver.performOneOperation(Insert(dummyKey, dummyValue))
      avlProver.performOneOperation(Insert(newKey, newValue))
      avlProver.generateProof()

      val digest = avlProver.digest
      val tree = KioskAvlTree(digest, KL, Some(VL))

      avlProver.performOneOperation(Lookup(newKey))

      val proof: Array[Byte] = avlProver.generateProof()

      TxUtil.createTx(
        Array(
          inBox,
          fundingBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            AvlLookup.address,
            minStorageRent,
            registers = Array(tree, KioskCollByte(newKey), KioskCollByte(newValue), KioskCollByte(proof)),
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

  ignore("LookupProd") {

    Client.usingContext { implicit ctx: BlockchainContext =>
      val minStorageRent = 1000000L

      val inBoxId = "63c4c9aec2dd180b7bc358bdb4b1f2d1586360a1855ae94475c146c4ab42dcab"
      val fundingBoxId = "d2e08bfa10f6c8798450013007e21150ef4fae76c813f35d81a6972819081228"

      val changeAddress = "9gQqZyxyjAptMbfW1Gydm3qaap11zd6X9DrABwgEE9eRdRvd27p"

      val proveDlogSecret = "-21120845569549261709579423621450797100274242707397768518154077936446211979699"

      val boxes = ctx.getBoxesById(inBoxId, fundingBoxId)
      val inBox: InputBox = boxes(0)
      val fundingBox: InputBox = boxes(1)

      val KL = 32
      val VL = 8

      val dummyKey = ADKey @@ Array.fill(KL)(0.toByte).take(KL)
      val dummyValue = ADValue @@ Array.fill(VL)(1.toByte).take(VL)

      val newKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Array.fill(KL)(10.toByte).take(KL)
      val newValue = ADValue @@ Array.fill(KL)(20.toByte).take(VL)

      val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))

      avlProver.performOneOperation(Insert(dummyKey, dummyValue))
      avlProver.performOneOperation(Insert(newKey, newValue))
      avlProver.generateProof()

      val digest = avlProver.digest
      val tree = KioskAvlTree(digest, KL, Some(VL))

      avlProver.performOneOperation(Lookup(newKey))

      val proof: Array[Byte] = avlProver.generateProof()

      TxUtil.createTx(
        Array(
          inBox,
          fundingBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            AvlLookup.address,
            minStorageRent,
            registers = Array(tree, KioskCollByte(newKey), KioskCollByte(newValue), KioskCollByte(proof)),
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
