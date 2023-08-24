import { Service } from 'typedi';
import { DataSource, Repository } from '@n8n/typeorm';
import { InstalledPackages } from '../entities/InstalledPackages';

@Service()
export class InstalledPackagesRepository extends Repository<InstalledPackages> {
	constructor(dataSource: DataSource) {
		super(InstalledPackages, dataSource.manager);
	}
}
