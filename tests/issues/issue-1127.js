var assert = require('assert');
var forge = require('../../');
describe('PKCS#12 MAC optional with no password', function() {
it('optional macData is okay rfc5280#section-4.1.1.2',async function() {
    const b64Pfx = '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' +
          'ZQA1ADYANAA0AGMANQA0MHkGCSsGAQQBgjcRATFsHmoATQBpAGMAcg' +
          'BvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMAQQAgAGEA' +
          'bgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjAC' +
          'AAUAByAG8AdgBpAGQAZQByMIID5wYJKoZIhvcNAQcGoIID2DCCA9QC' +
          'AQAwggPNBgkqhkiG9w0BBwEwHAYKKoZIhvcNAQwBAzAOBAjofJ+s8+' +
          '6CAgICB9CAggOgKKY/y0WZTbuOXeABYVpmuY5f1Ec3fD6fcNF1mOQm' +
          'wCcl9GZdx4VKGnsz9HOz17WF0KtLB+2c7q+9qc7Ndvp2L4mFkXyp7o' +
          'kKu72uPMDdEyeku2LEnopmYrFZmnoh/3KGLhr4FSQYJ9blY3Fk7Jxb' +
          'JhiElHWZO8XMky41PdCCwawQKWmFlCxNPqrsGr7qrKU3uTO3A7gpgY' +
          't1JlixfZeVeP/Z4ETvodvq4Cl3kcSQO+RSz0nDvqL6Z4F7PU2PSPbx' +
          'olnfqpqO6UnwXnLNyhJqX3D+FrPXjI+Nv8MshtdUoHFe5MciPEDDIQ' +
          'oo+3BYMgrYm+myv0/o9IUimLw8MH88U7lUm3KGVX+1hsdwMtzjeEtS' +
          'bW+meL03dSfJRu2J+oe/pLRUuP4WSCIiWW4fi6L24knG0jaGAh4njM' +
          '16naME9243gdcBs8QgBpwIo9zUGS21gfbsluS3rVEOaK9zQMQGupM6' +
          'VEeP3HSooz1jb2PYFcWqG6n+78KiMc+gMxBHLdXOKb7AbozOVPrR/g' +
          'JjyW8lMqDm9Drf+bdweDIJGQuZJKKbeLSszI/iaxetwO3DFI9L32iG' +
          'nHIFclIXZJ1VHG72ty4+ScA0YLYi92ONVqEmffIzoXcyR7521iFNKp' +
          '+ks6nagu+F0dl/KW0J22dKLmuNQhEteouoSXSHckyTdDIPqjt8a9vr' +
          'zWMqSlqlnVbKDkjvMzGqllsNG3asMQxHVbo1mdN1JkhYCzUF/tMekR' +
          'LAjEsEKHnqXQX8imQaq+i0YNfqPQ4Y7q8VlyOdIJgFGb3Gw0vhlr98' +
          'mwvfc1BpBThJ/Xs7w+Nx2PL6SW9Me3GyxxJ1eeSxnf5Lcpjzxe0sOs' +
          '4Z78F0Ox7xtmDhoWtD06TNj8YU65Vdz5PGkUkKndEBTBnEcSO0CCGX' +
          'S+wI/ILuANXjwQ5frBi4bFmIv+rwzOgpd3Vp1hIvQt1TydtvIssTyS' +
          'BofHtOL09hy3yZkndA1u6O23lyrLrADF1cgsBZ03xL+mMpeIYCDRFO' +
          'RrgUK/D7fIi19lmr17BzZL199edFfzAk93gI4uEUpp4dTbyqspi2rE' +
          'CtNYWWp4/g7xuTUlNkD8P/6IgkBDS4D162WWYdF9LXAFNRKrcc2Uzg' +
          'bTYso2OA6K25imD9yOM+uWC+G4WcW/S2xSxgHiRGz0sUuM4V+Qjela' +
          'I9J15ZRCTGNCz1qvN1TIaragHlv2+lQ91WDRd/QnIZAHcxj0j5wmh1' +
          'JFVLNkKRvDA7MB8wBwYFKw4DAhoEFMRoBxm71oVVRpPf9w7EBxc/rX' +
          'kDBBQv5N2Yn6i7hF+N3gzU7DWLCic+RAICB9A=';
    const p12Der = forge.util.decode64(b64Pfx);
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1);
    assert.ok(p12, 'pkcs12FromAsn1 should return an object');
    assert.ok(Array.isArray(p12.safeContents), 'safeContents should exist');
  });
});
