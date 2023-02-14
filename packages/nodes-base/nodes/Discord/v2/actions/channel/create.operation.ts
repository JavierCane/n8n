import type { IExecuteFunctions } from 'n8n-core';
import type { IDataObject, INodeExecutionData, INodeProperties } from 'n8n-workflow';
import { updateDisplayOptions } from '../../../../../utils/utilities';
import { discordApiRequest } from '../../transport';
import { categoryRLC } from '../common.description';

const properties: INodeProperties[] = [
	{
		displayName: 'Name',
		name: 'name',
		type: 'string',
		default: '',
		required: true,
		description: 'The name of the channel',
		placeholder: 'e.g. new-channel',
	},
	{
		displayName: 'Type',
		name: 'type',
		type: 'options',
		default: '0',
		required: true,
		description: 'The type of channel to create',
		options: [
			{
				name: 'Guild Text',
				value: '0',
			},
			{
				name: 'Guild Voice',
				value: '2',
			},
			// {
			// 	name: 'DM',
			// 	value: '1',
			// },
			// {
			// 	name: 'Group DM',
			// 	value: '3',
			// },
			{
				name: 'Guild Category',
				value: '4',
			},
			// {
			// 	name: 'Guild Store',
			// 	value: '6',
			// },
		],
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		options: [
			{
				displayName: 'Age-Restricted (NSFW)',
				name: 'nsfw',
				type: 'boolean',
				default: false,
				description: 'Whether the content of the channel might be nsfw (not safe for work)',
			},
			{
				displayName: 'Bitrate',
				name: 'bitrate',
				type: 'number',
				default: 8000,
				typeOptions: {
					minValue: 8000,
				},
				description: 'The bitrate (in bits) of the voice channel',
				displayOptions: {
					show: {
						'/type': ['2'],
					},
				},
			},
			categoryRLC,
			{
				displayName: 'Position',
				name: 'position',
				type: 'number',
				default: 1,
			},
			{
				displayName: 'Rate Limit Per User',
				name: 'rate_limit_per_user',
				type: 'number',
				default: 0,
				description: 'Amount of seconds a user has to wait before sending another message',
			},
			{
				displayName: 'Topic',
				name: 'topic',
				type: 'string',
				default: '',
				typeOptions: {
					rows: 2,
				},
				description: 'The channel topic description (0-1024 characters)',
				placeholder: 'e.g. This channel is about…',
			},
			{
				displayName: 'User Limit',
				name: 'user_limit',
				type: 'number',
				default: 0,
				typeOptions: {
					minValue: 0,
					maxValue: 99,
				},
				placeholder: 'e.g. 20',
				description:
					'The limit for the number of members that can be in the channel (0 refers to no limit)',
				displayOptions: {
					show: {
						'/type': ['2'],
					},
				},
			},
		],
	},
];

const displayOptions = {
	show: {
		resource: ['channel'],
		operation: ['create'],
	},
};

export const description = updateDisplayOptions(displayOptions, properties);

export async function execute(
	this: IExecuteFunctions,
	guildId: string,
): Promise<INodeExecutionData[]> {
	const returnData: INodeExecutionData[] = [];
	const items = this.getInputData();

	for (let i = 0; i < items.length; i++) {
		try {
			const name = this.getNodeParameter('name', i) as string;
			const type = this.getNodeParameter('type', i) as string;
			const options = this.getNodeParameter('options', i);

			if (options.categoryId) {
				options.parent_id = (options.categoryId as IDataObject).value;
				delete options.categoryId;
			}

			const body: IDataObject = {
				name,
				type,
				...options,
			};

			const response = await discordApiRequest.call(
				this,
				'POST',
				`/guilds/${guildId}/channels`,
				body,
			);

			const executionData = this.helpers.constructExecutionMetaData(
				this.helpers.returnJsonArray(response),
				{ itemData: { item: i } },
			);

			returnData.push(...executionData);
		} catch (error) {
			if (this.continueOnFail()) {
				const executionErrorData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray({ error: error.message }),
					{ itemData: { item: i } },
				);
				returnData.push(...executionErrorData);
				continue;
			}
			throw error;
		}
	}

	return returnData;
}
