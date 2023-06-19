import type { IExecuteFunctions } from 'n8n-core';
import type { IDataObject, INodeExecutionData, INodeProperties } from 'n8n-workflow';
import { updateDisplayOptions, wrapData } from '../../../../../utils/utilities';
import { taskStatusSelector } from '../common.description';

const properties: INodeProperties[] = [
	{
		displayName: 'Case ID',
		name: 'caseId',
		type: 'string',
		required: true,
		default: '',
	},
	{
		displayName: 'Title',
		name: 'title',
		type: 'string',
		required: true,
		default: '',
		description: 'Task details',
	},
	{
		...taskStatusSelector,
		required: true,
	},
	{
		displayName: 'Flag',
		name: 'flag',
		type: 'boolean',
		required: true,
		default: false,
		description: 'Whether to flag the task. Default=false.',
	},
	{
		displayName: 'Options',
		type: 'collection',
		name: 'options',
		placeholder: 'Add Option',
		default: {},
		options: [
			{
				displayName: 'Description',
				name: 'description',
				type: 'string',
				default: '',
				description: 'Task details',
			},
			{
				displayName: 'End Date',
				name: 'endDate',
				type: 'dateTime',
				default: '',
				description:
					'Date of the end of the task. This is automatically set when status is set to Completed.',
			},
			{
				displayName: 'Owner',
				name: 'owner',
				type: 'string',
				default: '',
				description:
					'User who owns the task. This is automatically set to current user when status is set to InProgress.',
			},
			{
				displayName: 'Start Date',
				name: 'startDate',
				type: 'dateTime',
				default: '',
				description:
					'Date of the beginning of the task. This is automatically set when status is set to Open.',
			},
		],
	},
];

const displayOptions = {
	show: {
		resource: ['alert'],
		operation: ['task'],
	},
};

export const description = updateDisplayOptions(displayOptions, properties);

export async function execute(this: IExecuteFunctions, i: number): Promise<INodeExecutionData[]> {
	const responseData: IDataObject[] = [];

	const executionData = this.helpers.constructExecutionMetaData(wrapData(responseData), {
		itemData: { item: i },
	});

	return executionData;
}