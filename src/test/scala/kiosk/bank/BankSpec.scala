package kiosk.bank

import kiosk.ErgoUtil.{addressToGroupElement => addr2Grp}
import kiosk.bank.Bank.minStorageRent
import kiosk.encoding.ScalaErgoConverters
import kiosk.encoding.ScalaErgoConverters.{stringToGroupElement => str2Grp}
import kiosk.ergo.{DhtData, KioskAvlTree, KioskBox, KioskCollByte, KioskGroupElement, KioskInt}
import kiosk.tx.TxUtil
import org.ergoplatform.appkit._
import org.scalatest.{Matchers, PropSpec}
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds
import scorex.crypto.authds.avltree.batch.Insert
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.hash.Sha256
import sigmastate.eval.CostingSigmaDslBuilder.longToByteArray
import supertagged.@@

class BankSpec extends PropSpec with Matchers with ScalaCheckDrivenPropertyChecks with HttpClientTesting {
  // create a valid tree
  val KL = 26
  val VL = 8
  val tree = new AVLTree(KL)
  // insert some data
  val ak = ADKey @@ "key1".getBytes()
  val aValue = ADValue @@ longToByteArray(1234L).toArray

  val aKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Sha256(ak).take(KL)
  tree.run(Insert(aKey, aValue)) // insert some data into tree

  val root: Array[Byte] = tree.rootHash()

  val ergoClient = createMockedErgoClient(MockData(Nil, Nil))

  val dummyNanoErgs = 10000000000000L
  val dummyScript = "sigmaProp(true)"
  val dummyTxId = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b809"
  val dummyBoxId = "5267556B58703273357638792F413F4428472B4B6250655368566D5971337436"
  val dummyIndex = 1.toShort
  val bankNFT = "404E635266556A586E327235753878214125442A472D4B6150645367566B5970"
  val bankTokenId = "34743777217A25432A46294A404E635266556A586E3272357538782F413F4428"

  val changeAddress = "9f5ZKbECVTm25JTRQHDHGM5ehC8tUw5g1fCBQ4aaE792rWBFrjK"

  val bankPubKey = KioskGroupElement(str2Grp(addr2Grp("9eiuh5bJtw9oWDVcfJnwTm1EHfK5949MEm5DStc2sD1TLwDSrpx")))
  val bankSecret = "37cc5cb5b54f98f92faef749a53b5ce4e9921890d9fb902b4456957d50791bd0"

  val isDefunct = KioskInt(0)

  property("Update root hash") {
    ergoClient.execute { implicit ctx: BlockchainContext =>
      val dummyBox = ctx // for funding transactions
        .newTxBuilder()
        .outBoxBuilder
        .value(dummyNanoErgs)
        .tokens(new ErgoToken(bankNFT, 1), new ErgoToken(bankTokenId, 100000000L))
        .contract(ctx.compileContract(ConstantsBuilder.empty(), dummyScript))
        .build()
        .convertToInputWith(dummyTxId, dummyIndex)
      val tx = TxUtil.createTx(
        Array(dummyBox),
        Array[InputBox](),
        Array(
          KioskBox(
            Bank.bankAddress,
            minStorageRent,
            registers = Array(KioskAvlTree(root, KL, Some(VL)), bankPubKey, isDefunct),
            tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
            creationHeight = Some(0)
          )
        ),
        fee = 1000000L,
        changeAddress,
        Array[String](),
        Array[DhtData](),
        false
      )
      val bankBox: InputBox = tx.getOutputsToSpend.get(0)

      val userPubKey: Array[Byte] = ScalaErgoConverters.getAddressFromString("9f9q6Hs7vXZSQwhbrptQZLkTx15ApjbEkQwWXJqD2NpaouiigJQ").script.bytes
      val userSecret = "5878ae48fe2d26aa999ed44437cffd2d4ba1543788cff48d490419aef7fc149d"
      val userValue = ADValue @@ longToByteArray(100L).toArray

      val userKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Sha256(userPubKey).take(KL)
      tree.run(Insert(userKey, userValue)) // insert some data into tree
      val newRootHash: Array[Byte] = tree.rootHash()
      val dummyCollByte1 = KioskCollByte("1".getBytes())
      val dummyCollByte2 = KioskCollByte("2".getBytes())
      val dummyInt = KioskInt(10)
      val newBankSpend = TxUtil.createTx(
        Array(
          bankBox
            .withContextVars(
              new ContextVar(0.toByte, dummyCollByte1.getErgoValue),
              new ContextVar(1.toByte, dummyCollByte2.getErgoValue),
              new ContextVar(2.toByte, dummyInt.getErgoValue),
            ),
          dummyBox
        ),
        Array[InputBox](),
        Array(
          KioskBox(
            Bank.bankAddress,
            minStorageRent,
            registers = Array(KioskAvlTree(newRootHash, KL, Some(VL)), bankPubKey, isDefunct),
            tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
            creationHeight = Some(ctx.getHeight)
          )
        ),
        fee = 1000000L,
        changeAddress,
        Array(bankSecret),
        Array[DhtData](),
        false
      )
    }
  }
  //  var newProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
}
