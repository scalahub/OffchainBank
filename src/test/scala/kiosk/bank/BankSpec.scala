package kiosk.bank

import kiosk.ErgoUtil.{addressToGroupElement => addr2Grp}
import kiosk.appkit.Client
import kiosk.bank.Bank.{minStorageRent, timeOut}
import kiosk.encoding.ScalaErgoConverters
import kiosk.encoding.ScalaErgoConverters.{stringToGroupElement => str2Grp}
import kiosk.ergo.{ByteArrayToBetterByteArray, DhtData, KioskAvlTree, KioskBox, KioskCollByte, KioskGroupElement, KioskInt}
import kiosk.tx.TxUtil
import org.ergoplatform.appkit._
import org.scalatest.{Matchers, PropSpec}
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds
import scorex.crypto.authds.avltree.batch.{BatchAVLProver, Insert, Lookup, Remove}
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.hash.{Blake2b256, Digest32}
import sigmastate.eval.CostingSigmaDslBuilder.longToByteArray
import supertagged.@@

class BankSpec extends PropSpec with Matchers with ScalaCheckDrivenPropertyChecks with HttpClientTesting {
  val KL = 32
  val VL = 8

  val dummyPubKey = ADKey @@ Array.fill(256)(0.toByte)
  val dummyValue = ADValue @@ longToByteArray(1234L).toArray
  val dummyKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Blake2b256(dummyPubKey).take(KL)

  val dummyNanoErgs = 10000000000000L
  val dummyScript = "sigmaProp(true)"
  val dummyTxId = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b809"
  val dummyBoxId = "5267556B58703273357638792F413F4428472B4B6250655368566D5971337436"
  val dummyIndex = 1.toShort
  val dummyTokenId = "44743777217A25432A46294A404E635266556A586E3272357538782F413F4428"
  val dummyCollByte1 = KioskCollByte("1".getBytes())
  val dummyCollByte2 = KioskCollByte("2".getBytes())

  val minStorageRentProd = 1000000L

  val changeAddress = "9f5ZKbECVTm25JTRQHDHGM5ehC8tUw5g1fCBQ4aaE792rWBFrjK"

  val bankNFT = "4b2d8b7beb3eaac8234d9e61792d270898a43934d6a27275e4f3a044609c9f2e"
  val bankTokenId = "7dbf52f31e8ba5b2be2e11201a24a4e286f8f6f8aeb0fa22937e80f11041f28b"
  val bankPubKey = KioskGroupElement(str2Grp(addr2Grp("9eiuh5bJtw9oWDVcfJnwTm1EHfK5949MEm5DStc2sD1TLwDSrpx")))
  val bankSecret = "37cc5cb5b54f98f92faef749a53b5ce4e9921890d9fb902b4456957d50791bd0"
  val bankTokenAmount = 10000L

  val dummyBoxIdProd = "1f6e9ccdde07d5211c760be5049de33d548ada308fb6f88b03ddebbccef1b020"
  val bankBoxIdProd = "8d13f40194ef5f444c017f3c88a424f90639b9976441e35e7b4fadeb9b5a1e11"
  val dummySecretProd = "-21120845569549261709579423621450797100274242707397768518154077936446211979699"

  val userAddress = "9f9q6Hs7vXZSQwhbrptQZLkTx15ApjbEkQwWXJqD2NpaouiigJQ"
  val userPubKey: Array[Byte] = ScalaErgoConverters.getAddressFromString(userAddress).script.bytes
  val userSecret = "5878ae48fe2d26aa999ed44437cffd2d4ba1543788cff48d490419aef7fc149d"
  val userBalance = 100L
  val userValue = ADValue @@ longToByteArray(userBalance).toArray
  val userKey: Array[Byte] @@ authds.ADKey.Tag = ADKey @@ Blake2b256(userPubKey).take(KL)

  val isNotDefunct = KioskInt(0)
  val isDefunct = KioskInt(1)

  def dummyBox(implicit ctx: BlockchainContext) = {
    ctx // for funding transactions
      .newTxBuilder()
      .outBoxBuilder
      .value(dummyNanoErgs)
      .tokens(new ErgoToken(bankNFT, 100000000L), new ErgoToken(bankTokenId, 100000000L), new ErgoToken(dummyTokenId, 10000000L))
      .contract(ctx.compileContract(ConstantsBuilder.empty(), dummyScript))
      .build()
      .convertToInputWith(dummyTxId, dummyIndex)
  }

  val ergoClient = createMockedErgoClient(MockData(Nil, Nil))

  property("Withdraw") {
    ergoClient.execute { implicit ctx: BlockchainContext =>
      Client.usingContext { ctxProd =>
        // user can withdraw if box is defunct
        noException shouldBe thrownBy {
          val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
          avlProver.performOneOperation(Insert(dummyKey, dummyValue))
          avlProver.performOneOperation(Insert(userKey, userValue))
          avlProver.generateProof()
          val digest32: Array[Byte] = avlProver.digest
          println("digest original" + digest32.encodeHex)

          val bankBox = TxUtil
            .createTx(
              Array(dummyBox),
              Array[InputBox](),
              Array(
                KioskBox(
                  Bank.bankAddress,
                  minStorageRent,
                  registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isDefunct),
                  tokens = Array((bankNFT, 1), (bankTokenId, bankTokenAmount)),
                  creationHeight = Some(0)
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

          val bankBoxProd = ctxProd.getBoxesById(bankBoxIdProd)(0)
          val dummyBoxProd = ctxProd.getBoxesById(dummyBoxIdProd)(0)

          bankBoxProd.getErgoTree shouldBe bankBox.getErgoTree
          bankBoxProd.getTokens.get(0).getId.toString shouldBe bankNFT
          bankBoxProd.getTokens.get(1).getId.toString shouldBe bankTokenId

          avlProver.performOneOperation(Lookup(userKey))
          val lookupProof: Array[Byte] = avlProver.generateProof()
          avlProver.performOneOperation(Remove(userKey))
          val removeProof: Array[Byte] = avlProver.generateProof()

          val digestOut = avlProver.digest
          println("remove proof" + removeProof.encodeHex)
          println("lookup proof" + lookupProof.encodeHex)
          println("digest " + digestOut.encodeHex)
          TxUtil.createTx(
            Array(
              bankBox
                .withContextVars(
                  new ContextVar(0.toByte, KioskCollByte(removeProof).getErgoValue),
                  new ContextVar(1.toByte, KioskCollByte(lookupProof).getErgoValue)
                ),
              dummyBox
            ),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(digestOut, KL, Some(VL)), bankPubKey, isDefunct),
                tokens = Array((bankNFT, 1), (bankTokenId, bankTokenAmount - userBalance))
              ),
              KioskBox(
                userAddress,
                minStorageRent,
                registers = Array(),
                tokens = Array((bankTokenId, userBalance))
              )
            ),
            fee = 1000000L,
            changeAddress,
            Array[String](),
            Array[DhtData](),
            false
          )

          val tx = TxUtil.createTx(
            Array(
              bankBoxProd
                .withContextVars(
                  new ContextVar(0.toByte, KioskCollByte(removeProof).getErgoValue),
                  new ContextVar(1.toByte, KioskCollByte(lookupProof).getErgoValue)
                ),
              dummyBoxProd
            ),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRentProd,
                registers = Array(KioskAvlTree(digestOut, KL, Some(VL)), bankPubKey, isDefunct),
                tokens = Array((bankNFT, 1), (bankTokenId, bankTokenAmount - userBalance))
              ),
              KioskBox(
                userAddress,
                minStorageRentProd,
                registers = Array(),
                tokens = Array((bankTokenId, userBalance))
              )
            ),
            fee = 1000000L,
            changeAddress,
            Array[String](dummySecretProd),
            Array[DhtData](),
            false
          )(ctxProd)

          println(tx.toJson(false))

          TxUtil.createTx(
            Array(
              bankBoxProd
                .withContextVars(
                  new ContextVar(0.toByte, KioskCollByte(removeProof).getErgoValue),
                  new ContextVar(1.toByte, KioskCollByte(lookupProof).getErgoValue)
                ),
              dummyBoxProd
            ),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRentProd,
                registers = Array(KioskAvlTree(digestOut, KL, Some(VL)), bankPubKey, isDefunct),
                tokens = Array((bankNFT, 1), (bankTokenId, bankTokenAmount - userBalance))
              ),
              KioskBox(
                userAddress,
                minStorageRentProd,
                registers = Array(),
                tokens = Array((bankTokenId, userBalance))
              )
            ),
            fee = 1000000L,
            changeAddress,
            Array[String](dummySecretProd),
            Array[DhtData](),
            true
          )(ctxProd)
        }
      }

      // user cannot withdraw if box is not defunct
      an[AssertionError] shouldBe thrownBy {
        val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
        avlProver.performOneOperation(Insert(dummyKey, dummyValue))
        avlProver.performOneOperation(Insert(userKey, userValue))
        avlProver.generateProof()

        val bankBox = TxUtil
          .createTx(
            Array(dummyBox),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
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
          .getOutputsToSpend
          .get(0)

        avlProver.performOneOperation(Lookup(userKey))
        val lookupProof: Array[Byte] = avlProver.generateProof()
        avlProver.performOneOperation(Remove(userKey))
        val removeProof: Array[Byte] = avlProver.generateProof()

        TxUtil.createTx(
          Array(
            bankBox
              .withContextVars(
                new ContextVar(0.toByte, KioskCollByte(removeProof).getErgoValue),
                new ContextVar(1.toByte, KioskCollByte(lookupProof).getErgoValue)
              ),
            dummyBox
          ),
          Array[InputBox](),
          Array(
            KioskBox(
              Bank.bankAddress,
              minStorageRent,
              registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
              tokens = Array((bankNFT, 1), (bankTokenId, 10000000L - userBalance)),
              creationHeight = Some(ctx.getHeight)
            ),
            KioskBox(
              userAddress,
              minStorageRent,
              registers = Array(),
              tokens = Array((bankTokenId, userBalance))
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
  }

  property("Update root hash") {
    ergoClient.execute { implicit ctx: BlockchainContext =>
      // bank can spend if box is not defunct
      noException shouldBe thrownBy {
        val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
        avlProver.performOneOperation(Insert(dummyKey, dummyValue))

        val bankBox = TxUtil
          .createTx(
            Array(dummyBox),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
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
          .getOutputsToSpend
          .get(0)

        avlProver.performOneOperation(Insert(userKey, userValue))

        TxUtil.createTx(
          Array(
            bankBox
              .withContextVars(
                new ContextVar(0.toByte, dummyCollByte1.getErgoValue),
                new ContextVar(1.toByte, dummyCollByte2.getErgoValue)
              ),
            dummyBox
          ),
          Array[InputBox](),
          Array(
            KioskBox(
              Bank.bankAddress,
              minStorageRent,
              registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
              tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
              creationHeight = Some(ctx.getHeight)
            ),
            KioskBox(
              changeAddress,
              minStorageRent,
              registers = Array(),
              tokens = Array((dummyTokenId, 1))
            )
          ),
          fee = 1000000L,
          changeAddress,
          Array(bankSecret),
          Array[DhtData](),
          false
        )
      }

      // bank cannot spend if box is not defunct
      the[Exception] thrownBy {
        val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
        avlProver.performOneOperation(Insert(dummyKey, dummyValue))

        val bankBox = TxUtil
          .createTx(
            Array(dummyBox),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isDefunct),
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
          .getOutputsToSpend
          .get(0)

        avlProver.performOneOperation(Insert(userKey, userValue))

        TxUtil.createTx(
          Array(
            bankBox
              .withContextVars(
                new ContextVar(0.toByte, dummyCollByte1.getErgoValue),
                new ContextVar(1.toByte, dummyCollByte2.getErgoValue)
              ),
            dummyBox
          ),
          Array[InputBox](),
          Array(
            KioskBox(
              Bank.bankAddress,
              minStorageRent,
              registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
              tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
              creationHeight = Some(ctx.getHeight)
            ),
            KioskBox(
              changeAddress,
              minStorageRent,
              registers = Array(),
              tokens = Array((dummyTokenId, 1))
            )
          ),
          fee = 1000000L,
          changeAddress,
          Array(bankSecret),
          Array[DhtData](),
          false
        )
      } should have message "Script reduced to false"
    }
  }

  property("Make defunct") {
    ergoClient.execute { implicit ctx: BlockchainContext =>
      // user can make defunct if height is crossed
      noException shouldBe thrownBy {
        val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
        avlProver.performOneOperation(Insert(dummyKey, dummyValue))
        avlProver.performOneOperation(Insert(userKey, userValue))
        avlProver.generateProof()

        val bankBox = TxUtil
          .createTx(
            Array(dummyBox),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
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
          .getOutputsToSpend
          .get(0)

        TxUtil.createTx(
          Array(
            bankBox
              .withContextVars(
                new ContextVar(0.toByte, dummyCollByte1.getErgoValue),
                new ContextVar(1.toByte, dummyCollByte2.getErgoValue)
              ),
            dummyBox
          ),
          Array[InputBox](),
          Array(
            KioskBox(
              Bank.bankAddress,
              minStorageRent,
              registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isDefunct),
              tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
              creationHeight = Some(ctx.getHeight)
            ),
            KioskBox(
              changeAddress,
              minStorageRent,
              registers = Array(),
              tokens = Array((dummyTokenId, 1))
            )
          ),
          fee = 1000000L,
          changeAddress,
          Array[String](),
          Array[DhtData](),
          false
        )
      }

      // cannot make defunct if height is not crossed
      an[AssertionError] shouldBe thrownBy {
        val avlProver = new BatchAVLProver[Digest32, Blake2b256.type](KL, Some(VL))
        avlProver.performOneOperation(Insert(dummyKey, dummyValue))
        avlProver.performOneOperation(Insert(userKey, userValue))
        avlProver.generateProof()

        val bankBox = TxUtil
          .createTx(
            Array(dummyBox),
            Array[InputBox](),
            Array(
              KioskBox(
                Bank.bankAddress,
                minStorageRent,
                registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isNotDefunct),
                tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
                creationHeight = Some(ctx.getHeight - timeOut)
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

        TxUtil.createTx(
          Array(
            bankBox
              .withContextVars(
                new ContextVar(0.toByte, dummyCollByte1.getErgoValue),
                new ContextVar(1.toByte, dummyCollByte2.getErgoValue)
              ),
            dummyBox
          ),
          Array[InputBox](),
          Array(
            KioskBox(
              Bank.bankAddress,
              minStorageRent,
              registers = Array(KioskAvlTree(avlProver.digest, KL, Some(VL)), bankPubKey, isDefunct),
              tokens = Array((bankNFT, 1), (bankTokenId, 10000000L)),
              creationHeight = Some(ctx.getHeight)
            ),
            KioskBox(
              changeAddress,
              minStorageRent,
              registers = Array(),
              tokens = Array((dummyTokenId, 1))
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
  }
}
