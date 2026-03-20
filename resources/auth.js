import { registerHooks } from '@harperfast/oauth';

async function fetchAvatarBlob(url) {
	try {
		const response = await fetch(url);
		if (!response.ok) return null;
		const buffer = Buffer.from(await response.arrayBuffer());
		return createBlob(buffer);
	} catch {
		return null;
	}
}

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		const { User } = tables;

		if (!oauthUser?.email) {
			throw new Error('OAuth provider did not provide email');
		}

		// Find existing user by email
		let user;
		for await (const record of User.search([{ attribute: 'email', value: oauthUser.email }])) {
			user = record;
			break;
		}

		const picture = oauthUser.metadata?.oauthClaims?.picture || '';

		// Fetch Google avatar as blob
		let avatarBlob = null;
		if (picture) {
			avatarBlob = await fetchAvatarBlob(picture);
		}

		if (!user) {
			const createData = {
				email: oauthUser.email,
				name: oauthUser.name,
				provider,
				role: 'analyst',
			};
			if (avatarBlob) {
				createData.picture = avatarBlob;
			}
			user = await User.create(createData);
		} else {
			const updateData = {
				email: user.email,
				name: oauthUser.name || user.name,
				provider: user.provider,
				role: user.role,
				lastLoginAt: new Date().toISOString(),
			};
			if (avatarBlob) {
				updateData.picture = avatarBlob;
			}
			await User.put(user.id, updateData);
		}

		return { user: String(user.id) };
	},
});
