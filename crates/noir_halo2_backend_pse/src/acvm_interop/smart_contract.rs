use crate::{circuit_translator::NoirHalo2Translator, halo2_plonk_api::OpcodeFlags, PseHalo2};
use acvm::{acir::circuit::Circuit, SmartContract};
use noir_halo2_backend_common::errors::BackendError;
use pse_halo2wrong::{
    curves::bn256::{Bn256, Fq, Fr, G1Affine},
    halo2::{
        plonk::VerifyingKey,
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
        SerdeFormat,
    },
};
use pse_snark_verifier::{
    loader::evm::EvmLoader,
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::rc::Rc;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

/// Generate the evm verifier of the circuit as Yul code
fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(params, vk, Config::kzg().with_num_instance(num_instance.clone()));
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
    
    // loader.yul_code()
    String::from("")
}

impl SmartContract for PseHalo2 {
    type Error = BackendError;

    /// Get ethereum verification contract from Verification Key
    fn eth_contract_from_vk(
        &self,
        mut common_reference_string: &[u8],
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        // get trusted setup params
        let params =
            ParamsKZG::<Bn256>::read_custom(&mut common_reference_string, SerdeFormat::RawBytes)
                .unwrap();

        // get opcode params informing circuit translation
        let opcode_flags = OpcodeFlags::default();

        // generate verifying key
        let vk = VerifyingKey::<G1Affine>::from_bytes::<NoirHalo2Translator<Fr>>(
            verification_key,
            SerdeFormat::RawBytes,
            opcode_flags,
        )
        .unwrap();

        // get number of public inputs used in circuit
        let num_instance = circuit.public_inputs().0.len();

        // generate Yul verifier and return
        Ok(gen_evm_verifier(&params, &vk, vec![num_instance]))
    }
}
