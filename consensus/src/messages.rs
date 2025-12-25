use crate::config::Committee;
use crate::core::{SeqNumber, FIN_PHASE, INIT_PHASE, LOCK_PHASE, OPT, PES};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt::{self};
use threshold_crypto::{PublicKeySet, SignatureShare};

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

// daniel: Add view, height, fallback in Block, Vote and QC
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC, //前一个节点的highQC
    pub author: PublicKey,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub payload: Vec<Digest>,
    pub signature: Signature,
    pub tag: u8,          //fallback
    pub round: SeqNumber, //fallback
    pub val: u8,          //dba
}

impl Block {
    pub async fn new(
        qc: QC,
        author: PublicKey,
        height: SeqNumber,
        epoch: SeqNumber,
        round: SeqNumber,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
        tag: u8,
    ) -> Self {
        let block = Self {
            qc,
            author,
            height,
            epoch,
            round,
            payload,
            signature: Signature::default(),
            tag,
            val: OPT,
        };

        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn parent(&self) -> &Digest {
        &self.qc.hash
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.qc.hash);
        hasher.update(self.tag.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, height {}, epoch {}, qc {:?}, payload_len {})",
            self.digest(),
            self.author,
            self.height,
            self.epoch,
            self.qc,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.height)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HVote {
    pub hash: Digest,
    pub height: SeqNumber,
    pub round: SeqNumber,
    pub epoch: SeqNumber,
    pub proposer: PublicKey, // proposer of the block
    pub tag: u8,
    pub author: PublicKey,
    pub signature: Signature,
    pub val: u8, //dba
}

impl HVote {
    pub async fn new(
        block: &Block,
        author: PublicKey,
        tag: u8,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            height: block.height,
            epoch: block.epoch,
            round: block.round,
            proposer: block.author,
            author,
            tag,
            signature: Signature::default(),
            val: OPT,
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for HVote {
    fn digest(&self) -> Digest {
        //与QC对应
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.tag.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.proposer.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for HVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "Vote(blockhash {}, proposer {}, height {}, epoch {},  voter {})",
            self.hash, self.proposer, self.height, self.epoch, self.author
        )
    }
}

impl fmt::Display for HVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Vote{}", self.hash)
    }
}

// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub enum PrePareProof {
//     OPTProof(QC),
//     PESProof(SPBProof),
// }

// impl PrePareProof {
//     pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
//         match self {
//             Self::OPTProof(qc) => {
//                 if *qc != QC::genesis() {
//                     qc.verify(committee)?;
//                 }
//                 Ok(())
//             }
//             Self::PESProof(proof) => {
//                 ensure!(proof.phase == FIN_PHASE, ConsensusError::InvalidFinProof());
//                 proof.verify(committee)
//             }
//         }
//     }
// }

#[derive(Clone, Serialize, Deserialize)]
pub struct PrePare {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub val: u8,
    pub qc: QC,
    pub signature: Signature,
}

impl PrePare {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        qc: QC,
        val: u8,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut prepare = Self {
            author,
            epoch,
            height,
            val,
            qc,
            signature: Signature::default(),
        };

        prepare.signature = signature_service.request_signature(prepare.digest()).await;

        return prepare;
    }

    pub fn verify(&self, committee: &Committee, fallback_length: SeqNumber) -> ConsensusResult<()> {
        ensure!(
            self.val == OPT || self.val == PES,
            ConsensusError::InvalidPrePareTag(self.val)
        );

        self.signature.verify(&self.digest(), &self.author)?;

        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        if self.qc.tag == PES && self.qc.round != fallback_length {
            return Err(ConsensusError::InvalidPreParePESQC(self.qc.round));
        }
        Ok(())
    }
}

impl Hash for PrePare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.val.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for PrePare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tag = String::from("Unkonw");
        if self.val == OPT {
            tag = "OPT".to_string();
        } else if self.val == PES {
            tag = "PES".to_string();
        }
        write!(
            f,
            "PrePare(tag {}, epoch {},height {}, author {})",
            tag, self.epoch, self.height, self.author
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SPBValue {
    pub val: u8,                                 //ABA输入
    pub signatures: Vec<(PublicKey, Signature)>, // 签名验证 0->f+1  1->2f+1
    pub block: Block,
    pub round: SeqNumber,
    pub phase: u8,
}

impl SPBValue {
    pub fn new(
        block: Block,
        round: SeqNumber,
        phase: u8,
        val: u8,
        signatures: Vec<(PublicKey, Signature)>,
    ) -> Self {
        Self {
            block,
            round,
            phase,
            val,
            signatures,
        }
    }

    pub fn aba_val_digest(val: u8) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(val.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }

    pub fn verify(
        &self,
        committee: &Committee,
        proof: &SPBProof,
        fallback_length: SeqNumber,
    ) -> ConsensusResult<()> {
        let mut flag = true;
        let weight = self.signatures.len() as u32;
        if self.val == OPT && weight < committee.random_coin_threshold() {
            flag = false;
        } else if self.val == PES && weight < committee.quorum_threshold() {
            flag = false;
        }
        if flag && self.block.height != 1 {
            // Check the signatures.
            Signature::verify_batch(&SPBValue::aba_val_digest(self.val), &self.signatures)
                .map_err(ConsensusError::from)?;
        } else if self.block.height != 1 {
            return Err(ConsensusError::InvalidPrePareTag(self.val));
        }

        if self.block.qc.round != fallback_length {
            return Err(ConsensusError::InvalidPreParePESQC(self.block.qc.round));
        }

        self.block.verify(committee)?;

        proof.verify(committee)?;

        Ok(())
    }
}

impl Hash for SPBValue {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.block.digest());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.phase.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SPBValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SPBValue(proposer {}, epoch {}, height {} ,round {}, pahse {})",
            self.block.author, self.block.epoch, self.block.height, self.round, self.phase
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SPBVote {
    pub hash: Digest,
    pub phase: u8,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub round: SeqNumber,
    pub proposer: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
}

impl SPBVote {
    pub async fn new(
        value: SPBValue,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut vote = Self {
            hash: value.digest(),
            phase: value.phase,
            height: value.block.height,
            epoch: value.block.epoch,
            round: value.round,
            proposer: value.block.author,
            author,
            signature: Signature::default(),
        };
        vote.signature = signature_service.request_signature(vote.digest()).await;
        return vote;
    }

    //验证门限签名是否正确
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.digest(), &self.author)?;
        // let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // // Check the signature.
        // ensure!(
        //     tss_pk.verify(&self.signature_share, &self.digest()),
        //     ConsensusError::InvalidThresholdSignature(self.author)
        // );

        Ok(())
    }
}

impl Hash for SPBVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.hash.clone());
        hasher.update(self.phase.to_be_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SPBVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "spb vote (author {}, height {}, round {}, phase {}, proposer {})",
            self.author, self.height, self.round, self.phase, self.proposer,
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SPBProof {
    pub phase: u8, //SPB的哪一个阶段
    pub round: SeqNumber,
    pub height: SeqNumber,
    pub shares: Vec<SPBVote>,
}

impl SPBProof {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        if self.phase <= INIT_PHASE {
            //第一阶段不做检查
            return Ok(());
        }

        if self.phase >= LOCK_PHASE {
            //检查门限签名是否正确
            let mut weight = 0;
            for share in self.shares.iter() {
                let name = share.author;
                let voting_rights = committee.stake(&name);
                ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(name));
                weight += voting_rights;
            }
            ensure!(
                weight >= committee.quorum_threshold(), //2f+1
                ConsensusError::SPBRequiresQuorum
            );

            for share in &self.shares {
                share.verify(committee)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for SPBProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SPBProof(height {} ,round {}, phase {})",
            self.height, self.round, self.phase
        )
    }
}

impl fmt::Display for SPBProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "SPBProof(round {}, phase {})", self.round, self.phase)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MDoneAndShare {
    pub author: PublicKey,
    pub signature: Signature,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber,
    pub share: RandomnessShare,
}

impl MDoneAndShare {
    pub async fn new(
        author: PublicKey,
        mut signature_service: SignatureService,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        share: RandomnessShare,
    ) -> Self {
        let mut done = Self {
            author,
            signature: Signature::default(),
            epoch,
            height,
            round,
            share,
        };
        done.signature = signature_service.request_signature(done.digest()).await;
        return done;
    }

    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        self.signature.verify(&self.digest(), &self.author)?;
        self.share.verify(committee, pk_set)?;
        Ok(())
    }
}

impl Hash for MDoneAndShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for MDoneAndShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "Done(author {},height {},epoch {},round {})",
            self.author, self.height, self.epoch, self.round
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum PreVoteTag {
    Yes(SPBValue, SPBProof),
    No(),
    // No(SignatureShare)
}

impl PreVoteTag {
    pub async fn new_yes(v: SPBValue, p: SPBProof) -> PreVoteTag {
        Self::Yes(v, p)
    }

    pub async fn new_no() -> PreVoteTag {
        Self::No()
    }

    pub fn verify(&self, committee: &Committee, fallback_length: SeqNumber) -> ConsensusResult<()> {
        match self {
            Self::Yes(v, p) => v.verify(committee, p, fallback_length),
            Self::No() => Ok(()),
        }
    }

    pub fn is_yes(&self) -> bool {
        match self {
            Self::Yes(..) => true,
            _ => false,
        }
    }
}

impl fmt::Debug for PreVoteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreVoteTag::Yes(..) => write!(f, "PreVote-Yes"),
            PreVoteTag::No(..) => write!(f, "PreVote-No"),
        }
    }
}

impl fmt::Display for PreVoteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreVoteTag::Yes(..) => write!(f, "PreVote-Yes"),
            PreVoteTag::No(..) => write!(f, "PreVote-No"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MPreVote {
    pub author: PublicKey,
    pub signature: Signature,
    pub leader: PublicKey,
    pub round: SeqNumber,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub tag: PreVoteTag,
}

impl MPreVote {
    pub async fn new(
        author: PublicKey,
        leader: PublicKey,
        mut signature_service: SignatureService,
        round: SeqNumber,
        height: SeqNumber,
        epoch: SeqNumber,
        tag: PreVoteTag,
    ) -> Self {
        let mut pvote = Self {
            author,
            signature: Signature::default(),
            leader,
            round,
            height,
            epoch,
            tag,
        };
        pvote.signature = signature_service.request_signature(pvote.digest()).await;
        return pvote;
    }

    pub fn verify(&self, committee: &Committee, fallback_length: SeqNumber) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        //check signature
        self.signature.verify(&self.digest(), &self.author)?;

        //chekc tag
        self.tag.verify(committee, fallback_length)?;

        Ok(())
    }

    pub fn is_yes(&self) -> bool {
        self.tag.is_yes()
    }
}

impl Hash for MPreVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.leader.0);
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.tag.to_string());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for MPreVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PreVote(author {}, leader {},epoch {}, height {},round {}, tag {},)",
            self.author, self.leader, self.epoch, self.height, self.round, self.tag
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub enum MVoteTag {
    Yes(SPBValue, SPBProof, SPBVote),
    No(),
}

impl MVoteTag {
    pub async fn new_yes(
        author: PublicKey,
        value: SPBValue,
        proof: SPBProof,
        signature_service: SignatureService,
    ) -> Self {
        let spbvote = SPBVote::new(value.clone(), author, signature_service).await;
        Self::Yes(value, proof, spbvote)
    }

    pub async fn new_no() -> Self {
        Self::No()
    }

    pub fn verify(&self, committee: &Committee, fallback_length: SeqNumber) -> ConsensusResult<()> {
        match self {
            Self::Yes(value, proof, prevote) => {
                value.verify(committee, proof, fallback_length)?;
                prevote.verify(committee)?;
                Ok(())
            }
            Self::No() => Ok(()),
        }
    }
}

impl fmt::Debug for MVoteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yes(..) => {
                write!(f, "Vote-Yes")
            }
            Self::No(..) => {
                write!(f, "Vote-No")
            }
        }
    }
}

impl fmt::Display for MVoteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yes(..) => {
                write!(f, "Vote-Yes")
            }
            Self::No(..) => {
                write!(f, "Vote-No")
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MVote {
    pub author: PublicKey,
    pub leader: PublicKey,
    pub round: SeqNumber,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub signature: Signature,
    pub tag: MVoteTag,
}

impl MVote {
    pub async fn new(
        author: PublicKey,
        leader: PublicKey,
        mut signature_service: SignatureService,
        round: SeqNumber,
        height: SeqNumber,
        epoch: SeqNumber,
        tag: MVoteTag,
    ) -> Self {
        let mut pvote = Self {
            author,
            signature: Signature::default(),
            leader,
            round,
            height,
            epoch,
            tag,
        };
        pvote.signature = signature_service.request_signature(pvote.digest()).await;
        return pvote;
    }

    pub fn verify(
        &self,
        committee: &Committee,
        _pk_set: &PublicKeySet,
        fallback_length: SeqNumber,
    ) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        //check signature
        self.signature.verify(&self.digest(), &self.author)?;

        //chekc tag
        self.tag.verify(committee, fallback_length)?;

        Ok(())
    }
}

impl Hash for MVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.tag.to_string());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for MVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MVote(author {}, leader {},epoch {}, height {}, round {}, tag {},)",
            self.author, self.leader, self.epoch, self.height, self.round, self.tag
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MHalt {
    pub author: PublicKey,
    pub leader: PublicKey,
    pub value: SPBValue,
    pub proof: SPBProof,
    pub round: SeqNumber,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub signature: Signature,
}

impl MHalt {
    pub async fn new(
        author: PublicKey,
        leader: PublicKey,
        value: SPBValue,
        proof: SPBProof,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut halt = Self {
            round: proof.round,
            height: proof.height,
            epoch: value.block.epoch,
            author,
            value,
            leader,
            proof,
            signature: Signature::default(),
        };
        halt.signature = signature_service.request_signature(halt.digest()).await;
        return halt;
    }

    pub fn verify(
        &self,
        committee: &Committee,
        _pk_set: &PublicKeySet,
        fallback_length: SeqNumber,
    ) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        //check signature
        self.signature.verify(&self.digest(), &self.author)?;

        //check proof
        ensure!(
            self.proof.phase == FIN_PHASE, //是否为finsh phase 阶段
            ConsensusError::InvalidFinProof()
        );
        self.value.verify(committee, &self.proof, fallback_length)?;

        Ok(())
    }
}

impl Hash for MHalt {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for MHalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MHalt(author {},epoch {}, height {} ,round {}, leader {},)",
            self.author, self.epoch, self.height, self.round, self.leader
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub round: SeqNumber,
    pub tag: u8,
    pub proposer: PublicKey, // proposer of the block
    pub acceptor: PublicKey, // Node that accepts the QC and builds its f-chain extending it
    pub votes: Vec<(PublicKey, Signature)>,
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.height != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0; //票数
        let mut used = HashSet::new(); //防止重复统计
        for (name, _) in self.votes.iter() {
            ensure!(
                !used.contains(name),
                ConsensusError::AuthorityReuseinQC(*name)
            );
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)?;
        Ok(())
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        //与HVote对应
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.tag.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.proposer.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "QC(hash {}, height {},  proposer {})",
            self.hash, self.height, self.proposer
        )
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.height == other.height
            && self.epoch == self.epoch
            && self.proposer == other.proposer
    }
}

// leader选举时 每个发送自己的randomshare
#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub height: SeqNumber,
    pub epoch: SeqNumber,
    pub round: SeqNumber,
    pub author: PublicKey,
    pub signature_share: SignatureShare,
    // pub high_qc: Option<QC>, // attach its height-2 qc in the randomness share as an optimization
}

impl RandomnessShare {
    pub async fn new(
        height: SeqNumber,
        epoch: SeqNumber,
        round: SeqNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(round.to_le_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service
            .request_tss_signature(digest)
            .await
            .unwrap();
        Self {
            round,
            height,
            epoch,
            author,
            signature_share,
        }
    }

    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            tss_pk.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidThresholdSignature(self.author)
        );

        Ok(())
    }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RandomnessShare (author {}, height {},round {})",
            self.author, self.height, self.round,
        )
    }
}

// f+1 个 RandomnessShare 合成的
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct RandomCoin {
    pub height: SeqNumber, //
    pub epoch: SeqNumber,
    pub round: SeqNumber,
    pub leader: PublicKey, // elected leader of the view
    pub shares: Vec<RandomnessShare>,
}

impl RandomCoin {
    // pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
    //     // Ensure the QC has a quorum.
    //     let mut weight = 0;
    //     let mut used = HashSet::new();
    //     for share in self.shares.iter() {
    //         let name = share.author;
    //         ensure!(
    //             !used.contains(&name),
    //             ConsensusError::AuthorityReuseinCoin(name)
    //         );
    //         let voting_rights = committee.stake(&name);
    //         ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(name));
    //         used.insert(name);
    //         weight += voting_rights;
    //     }
    //     ensure!(
    //         weight >= committee.random_coin_threshold(), //f+1
    //         ConsensusError::RandomCoinRequiresQuorum
    //     );

    //     let mut sigs = BTreeMap::new(); //构建BTree选择leader
    //                                     // Check the random shares.
    //     for share in &self.shares {
    //         share.verify(committee, pk_set)?;
    //         sigs.insert(committee.id(share.author), share.signature_share.clone());
    //     }
    //     if let Ok(sig) = pk_set.combine_signatures(sigs.iter()) {
    //         let id = usize::from_be_bytes((&sig.to_bytes()[0..8]).try_into().unwrap())
    //             % committee.size();
    //         let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
    //         keys.sort();
    //         let leader = keys[id];
    //         ensure!(
    //             leader == self.leader,
    //             ConsensusError::RandomCoinWithWrongLeader
    //         );
    //     } else {
    //         ensure!(true, ConsensusError::RandomCoinWithWrongShares);
    //     }

    //     Ok(())
    // }
}

impl fmt::Debug for RandomCoin {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RandomCoin(epoch {}, height {},round {}, leader {})",
            self.epoch, self.height, self.round, self.leader
        )
    }
}
