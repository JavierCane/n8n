import type { IExecuteFunctions } from 'n8n-core';
import type { IDataObject, INodeExecutionData, INodeProperties } from 'n8n-workflow';
import { updateDisplayOptions, wrapData } from '../../../../../utils/utilities';

const properties: INodeProperties[] = [
	{
		displayName: 'Log ID',
		name: 'id',
		type: 'string',
		default: '',
		required: true,
	},
];

const displayOptions = {
	show: {
		resource: ['log'],
		operation: ['get'],
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