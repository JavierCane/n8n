import { mock } from 'jest-mock-extended';
import type { ILogger } from 'n8n-workflow';
import type { Repository } from 'typeorm';
import type { Config } from '@/config';
import { OAuth2CredentialController } from '@/controllers';
import type { SharedCredentials } from '@db/entities/SharedCredentials';
import type { User } from '@db/entities/User';
import type { CredentialsHelper } from '@/CredentialsHelper';
import type { ICredentialsDb, IExternalHooksClass } from '@/Interfaces';
import type { OAuthRequest } from '@/requests';
import { BadRequestError, NotFoundError } from '@/ResponseHelper';

jest.mock('crypto-js', () => ({
	AES: {
		encrypt: () => '',
	},
}));

jest.mock(
	'csrf',
	() =>
		class Csrf {
			secretSync() {
				return 'csrf-secret';
			}

			create() {
				return 'token';
			}
		},
);

describe('OAuth2CredentialController', () => {
	const config = mock<Config>();
	config.getEnv.mockImplementation((key) => {
		if (key === 'endpoints.rest') return 'rest';
	});
	const logger = mock<ILogger>();
	const credentialsHelper = mock<CredentialsHelper>({ encryptionKey: 'test' });
	const externalHooks = mock<IExternalHooksClass>();
	const credentialsRepository = mock<Repository<ICredentialsDb>>();
	const sharedCredentialsRepository = mock<Repository<SharedCredentials>>();
	const controller = new OAuth2CredentialController(
		config,
		logger,
		credentialsHelper,
		externalHooks,
		credentialsRepository,
		sharedCredentialsRepository,
	);

	const user = mock<User>({
		id: '123',
		password: 'password',
		authIdentities: [],
		globalRoleId: '1',
	});

	describe('getAuthUri', () => {
		it('should throw a BadRequestError when credentialId is missing in the query', async () => {
			const req = mock<OAuthRequest.OAuth2Credential.Auth>({ query: { id: '' } });
			await expect(controller.getAuthUri(req)).rejects.toThrowError(
				new BadRequestError('Required credential ID is missing'),
			);
		});

		it('should throw a NotFoundError when no matching credential is found for the user', async () => {
			const req = mock<OAuthRequest.OAuth2Credential.Auth>({ user, query: { id: '1' } });
			sharedCredentialsRepository.findOne.mockResolvedValueOnce(null);
			await expect(controller.getAuthUri(req)).rejects.toThrowError(
				new NotFoundError('Credential not found'),
			);
		});

		it('should throw an InternalServerError if Encryption-Key is missing', async () => {
			const req = mock<OAuthRequest.OAuth2Credential.Auth>({ user, query: { id: '1' } });
			sharedCredentialsRepository.findOne.mockResolvedValueOnce(
				mock<SharedCredentials>({
					credentials: { id: '1', type: 'googleDriveOAuth2Api' },
				}),
			);
			credentialsHelper.getDecrypted.mockResolvedValueOnce({});
			credentialsHelper.applyDefaultsAndOverwrites.mockReturnValue({
				clientId: 'test-client-id',
				authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
			});
			const redirectUri = await controller.getAuthUri(req);
			expect(redirectUri).toEqual(
				'https://accounts.google.com/o/oauth2/v2/auth?client_id=test-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A5678%2Frest%2Foauth2-credential%2Fcallback&response_type=code&state=eyJ0b2tlbiI6InRva2VuIiwiY2lkIjoiMSJ9&scope=openid',
			);
		});
	});
});
