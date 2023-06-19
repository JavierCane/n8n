import type { INodeProperties } from 'n8n-workflow';
import { TLP } from '../helpers/interfaces';

export const returnAllAndLimit: INodeProperties[] = [
	{
		displayName: 'Return All',
		name: 'returnAll',
		type: 'boolean',
		default: false,
		description: 'Whether to return all results or only up to a given limit',
	},
	{
		displayName: 'Limit',
		name: 'limit',
		type: 'number',
		typeOptions: {
			minValue: 1,
		},
		default: 50,
		description: 'Max number of results to return',
		displayOptions: {
			show: {
				returnAll: [false],
			},
		},
	},
];

export const responderSelector: INodeProperties = {
	displayName: 'Responder Name or ID',
	name: 'responder',
	type: 'options',
	description:
		'Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code-examples/expressions/">expression</a>',
	required: true,
	default: '',
	typeOptions: {
		loadOptionsDependsOn: ['id'],
		loadOptionsMethod: 'loadResponders',
	},
	displayOptions: {
		hide: {
			id: [''],
		},
	},
};

export const tlpSelector: INodeProperties = {
	displayName: 'Traffict Light Protocol (TLP)',
	name: 'tlp',
	type: 'options',
	default: 2,
	options: [
		{
			name: 'White',
			value: TLP.white,
		},
		{
			name: 'Green',
			value: TLP.green,
		},
		{
			name: 'Amber',
			value: TLP.amber,
		},
		{
			name: 'Red',
			value: TLP.red,
		},
	],
};

export const severitySelector: INodeProperties = {
	displayName: 'Severity',
	name: 'severity',
	type: 'options',
	options: [
		{
			name: 'Low',
			value: 1,
		},
		{
			name: 'Medium',
			value: 2,
		},
		{
			name: 'High',
			value: 3,
		},
	],
	default: 2,
	description: 'Severity of the alert. Default=Medium.',
};

export const customFields: INodeProperties = {
	displayName: 'Custom Fields',
	name: 'customFieldsUi',
	type: 'fixedCollection',
	default: {},
	typeOptions: {
		multipleValues: true,
	},
	placeholder: 'Add Custom Field',
	options: [
		{
			displayName: 'Custom Field',
			name: 'customFields',
			values: [
				{
					displayName: 'Field Name or ID',
					name: 'field',
					type: 'options',
					description:
						'Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code-examples/expressions/">expression</a>',
					typeOptions: {
						loadOptionsMethod: 'loadCustomFields',
					},
					default: 'Custom Field',
				},
				{
					displayName: 'Value',
					name: 'value',
					type: 'string',
					default: '',
					description: 'Custom Field value. Use an expression if the type is not a string.',
				},
			],
		},
	],
};

export const observableDataType: INodeProperties = {
	displayName: 'Data Type Name or ID',
	name: 'dataType',
	type: 'options',
	default: '',
	typeOptions: {
		loadOptionsMethod: 'loadObservableTypes',
	},
	description:
		'Type of the observable. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code-examples/expressions/">expression</a>.',
};

export const alertStatusSelector: INodeProperties = {
	displayName: 'Status',
	name: 'status',
	type: 'options',
	options: [
		{
			name: 'New',
			value: 'New',
		},
		{
			name: 'Updated',
			value: 'Updated',
		},
		{
			name: 'Ignored',
			value: 'Ignored',
		},
		{
			name: 'Imported',
			value: 'Imported',
		},
	],
	default: 'New',
	description: 'Status of the alert',
};

export const caseStatusSelector: INodeProperties = {
	displayName: 'Status',
	name: 'status',
	type: 'options',
	options: [
		{
			name: 'Open',
			value: 'Open',
		},
		{
			name: 'Resolved',
			value: 'Resolved',
		},
		{
			name: 'Deleted',
			value: 'Deleted',
		},
	],
	default: 'Open',
};

export const observableStatusSelector: INodeProperties = {
	displayName: 'Status',
	name: 'Status',
	type: 'options',
	default: 'Ok',
	options: [
		{
			name: 'Ok',
			value: 'Ok',
		},
		{
			name: 'Deleted',
			value: 'Deleted',
		},
	],
	description: 'Status of the observable. Default=Ok.',
};

export const taskStatusSelector: INodeProperties = {
	displayName: 'Status',
	name: 'status',
	type: 'options',
	default: 'Waiting',
	options: [
		{
			name: 'Cancel',
			value: 'Cancel',
		},
		{
			name: 'Completed',
			value: 'Completed',
		},
		{
			name: 'InProgress',
			value: 'InProgress',
		},
		{
			name: 'Waiting',
			value: 'Waiting',
		},
	],
	description: 'Status of the task. Default=Waiting.',
};

export const filtersCollection: INodeProperties = {
	displayName: 'Filters',
	name: 'filters',
	type: 'collection',
	default: {},
	placeholder: 'Add a Filter',
	options: [
		customFields,
		{
			displayName: 'Description',
			name: 'description',
			type: 'string',
			default: '',
		},
		{
			displayName: 'End Date',
			name: 'endDate',
			type: 'dateTime',
			default: '',
			description: 'Resolution date',
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Follow',
			name: 'follow',
			type: 'boolean',
			default: false,
			description: 'Whether the alert becomes active when updated default=true',
			displayOptions: {
				show: {
					'/resource': ['alert'],
				},
			},
		},
		{
			displayName: 'Flag',
			name: 'flag',
			type: 'boolean',
			default: false,
			// eslint-disable-next-line n8n-nodes-base/node-param-description-boolean-without-whether
			description: 'Flag of the case default=false',
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Impact Status',
			name: 'impactStatus',
			type: 'options',
			default: '',
			options: [
				{
					name: 'No Impact',
					value: 'NoImpact',
				},
				{
					name: 'With Impact',
					value: 'WithImpact',
				},
				{
					name: 'Not Applicable',
					value: 'NotApplicable',
				},
			],
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Owner',
			name: 'owner',
			type: 'string',
			default: '',
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Resolution Status',
			name: 'resolutionStatus',
			type: 'options',
			default: '',
			options: [
				{
					value: 'Duplicated',
					name: 'Duplicated',
				},
				{
					value: 'False Positive',
					name: 'FalsePositive',
				},
				{
					value: 'Indeterminate',
					name: 'Indeterminate',
				},
				{
					value: 'Other',
					name: 'Other',
				},
				{
					value: 'True Positive',
					name: 'TruePositive',
				},
			],
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		severitySelector,
		{
			displayName: 'Start Date',
			name: 'startDate',
			type: 'dateTime',
			default: '',
			description: 'Date and time of the begin of the case default=now',
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			...caseStatusSelector,
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Summary',
			name: 'summary',
			type: 'string',
			default: '',
			description: 'Summary of the case, to be provided when closing a case',
			displayOptions: {
				show: {
					'/resource': ['case'],
				},
			},
		},
		{
			displayName: 'Tags',
			name: 'tags',
			type: 'string',
			default: '',
			placeholder: 'tag,tag2,tag3...',
		},
		{
			displayName: 'Title',
			name: 'title',
			type: 'string',
			default: '',
		},
		tlpSelector,
	],
};