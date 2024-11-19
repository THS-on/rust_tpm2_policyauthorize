use std::{fs::File, io::Read, str::FromStr};

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcGroup,
    nid::Nid,
};
pub use tss_esapi::Error;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{PublicAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        CreateKeyResult, CreatePrimaryKeyResult, Digest, EccParameter, EccPoint, EccScheme,
        EccSignature, HashScheme, KeyDerivationFunctionScheme, MaxBuffer, Name,
        PcrSelectionListBuilder, PublicBuilder, PublicEccParametersBuilder, Signature,
        SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::DeviceConfig,
};
use tss_esapi::{
    constants::SessionType,
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSlot, SymmetricDefinition},
    Context, TctiNameConf,
};

fn create_primary(context: &mut Context) -> Result<CreatePrimaryKeyResult, Error> {
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP384)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        })
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;

    let primary_object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;

    let primary_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(primary_object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;

    context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(
            Hierarchy::Owner,
            primary_public.clone(),
            None,
            None,
            None,
            None,
        )
    })
}

fn load_external_key(context: &mut Context) -> Result<(KeyHandle, Name), Error> {
    let signing_key = openssl::ec::EcKey::public_key_from_pem(
        &read_file_to_buf("data/signing_key_public.pem").unwrap(),
    )
    .unwrap();
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    signing_key
        .public_key()
        .affine_coordinates_gfp(group.as_ref(), &mut x, &mut y, &mut ctx)
        .expect("extract coords");

    let object_attributes = ObjectAttributesBuilder::new()
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .with_user_with_auth(true)
        .build()?;

    let ecc_attributes = PublicEccParametersBuilder::new()
        .with_curve(EccCurve::NistP384)
        .with_ecc_scheme(EccScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_ecc_parameters(ecc_attributes)
        .with_object_attributes(object_attributes)
        .with_ecc_unique_identifier(EccPoint::new(
            EccParameter::try_from(x.to_vec())?,
            EccParameter::try_from(y.to_vec())?,
        ))
        .build()?;

    let handle = context
        .execute_with_nullauth_session(|ctx| ctx.load_external_public(public, Hierarchy::Owner))?;

    let name = context.tr_get_name(handle.into())?;
    Ok((handle, name))
}

fn set_policy(context: &mut Context, session: AuthSession) -> Result<(), Error> {
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, vec![PcrSlot::Slot7].as_slice())
        .build()?;

    let (_update_counter, pcr_sel, pcr_data) =
        context.execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))?;

    let concatenated_pcr_values = pcr_data
        .value()
        .iter()
        .map(|x| x.value())
        .collect::<Vec<&[u8]>>()
        .concat();
    let concatenated_pcr_values = MaxBuffer::try_from(concatenated_pcr_values)?;

    let (pcr_hashed_data, _pcr_ticket) = context.execute_without_session(|ctx| {
        ctx.hash(
            concatenated_pcr_values,
            HashingAlgorithm::Sha256,
            Hierarchy::Owner,
        )
    })?;
    context.policy_pcr(
        session.try_into()?,
        pcr_hashed_data.clone(),
        pcr_sel.clone(),
    )?;

    Ok(())
}

fn read_file_to_buf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    Ok(buf)
}

fn create_key_with_policy(
    context: &mut Context,
    policy: Digest,
    primary: &CreatePrimaryKeyResult,
) -> Result<CreateKeyResult, Error> {
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP384)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;

    let key_object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .build()?;

    let key_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(key_object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .with_auth_policy(policy)
        .build()?;

    context.execute_with_nullauth_session(|ctx| {
        ctx.create(primary.key_handle, key_public, None, None, None, None)
    })
}

fn run() -> Result<(), Error> {
    env_logger::init();
    let device = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm1")?);
    let mut context = Context::new(device)?;

    let primary = create_primary(&mut context)?;
    println!("Created primary key");

    let authorized_policy = Digest::try_from(read_file_to_buf("data/authorized.policy").unwrap())?;

    let key: CreateKeyResult =
        create_key_with_policy(&mut context, authorized_policy.clone(), &primary)?;
    println!("Created Key");

    let key_handle = context.execute_with_nullauth_session(|ctx| {
        ctx.load(primary.key_handle, key.out_private, key.out_public)
    })?;
    println!("Loaded key");

    // Create digest to sign
    let data = MaxBuffer::try_from(vec![0])?;
    let (digest, ticket) = context.execute_without_session(|ctx| {
        ctx.hash(data, HashingAlgorithm::Sha256, Hierarchy::Owner)
    })?;
    println!("Hashed data");

    // Create fresh session
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .unwrap();

    let (signing_key_handle, name) = load_external_key(&mut context)?;
    let pcr_policy_raw = read_file_to_buf("data/pcr.policy_desired").unwrap();
    let pcr_policy_digest = Digest::try_from(pcr_policy_raw.clone())?;
    let pcr_policy = MaxBuffer::try_from(pcr_policy_raw.clone())?;

    let signature: openssl::ecdsa::EcdsaSig =
        openssl::ecdsa::EcdsaSig::from_der(&read_file_to_buf("data/pcr.signature").unwrap())
            .unwrap();
    let pcr_policy_signature = Signature::EcDsa(EccSignature::create(
        HashingAlgorithm::Sha256,
        EccParameter::try_from(signature.r().to_vec())?,
        EccParameter::try_from(signature.s().to_vec())?,
    )?);

    let (pcr_policy_digest_digest, _) = context.execute_without_session(|ctx| {
        ctx.hash(
            pcr_policy.clone(),
            HashingAlgorithm::Sha256,
            Hierarchy::Owner,
        )
    })?;

    let pcr_ticket = context.verify_signature(
        signing_key_handle,
        pcr_policy_digest_digest,
        pcr_policy_signature,
    )?;

    set_policy(&mut context, session)?;

    context.policy_authorize(
        session.try_into()?,
        pcr_policy_digest,
        Default::default(),
        &name,
        pcr_ticket,
    )?;

    println!("policy setup complete");

    let signature = context.execute_with_session(Some(session), |ctx| {
        ctx.sign(
            key_handle,
            digest,
            SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            ticket,
        )
    })?;
    println!("Generated signature");
    println!("Signature {:?}", signature);

    Ok(())
}

fn main() {
    let res = run();
    match res {
        Ok(_) => {}
        Err(e) => {
            println!("{}\n\n", e);
            Err::<(), tss_esapi::Error>(e).unwrap();
        }
    };
}
